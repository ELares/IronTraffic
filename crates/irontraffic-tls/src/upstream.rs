// SPDX-License-Identifier: MIT OR Apache-2.0

//! Upstream TLS: the compiled configuration and verifier for dialing one upstream cluster.
//!
//! This module is the mirror image of `verify_client.rs`: that module verifies who is
//! connecting to us, this module verifies who we are connecting to. The governing failure
//! mode is the same, and it is fail open. Caddy shipped CVE-2026-27586, mTLS silently failing
//! open when a CA file was missing or malformed; the correction there was making
//! [`crate::verify_client::TrustAnchors`] impossible to construct empty. The same correction
//! applies here: [`UpstreamTls::compile`] refuses to produce a configuration that would accept
//! any peer, unless the operator sets both `insecureSkipVerify` and `iAcceptTheRisk`
//! explicitly.
//!
//! The configuration shape is Gateway API `BackendTLSPolicy` exactly, because that
//! specification deliberately separates `hostname` (the SNI we send) from `subjectAltNames`
//! (the identity we accept). That separation is not incidental: `spiffe://td/ns/x/sa/y` is not
//! a valid SNI, so an implementation that tries to verify identity by handing rustls the
//! configured identity as a `ServerName` cannot express SPIFFE at all. [`UpstreamVerifier`]
//! keeps the two checks structurally separate: chain verification always runs through
//! rustls-webpki, and identity matching, when configured, runs as a second, independent step
//! against the peer's `dNSName` and `uniformResourceIdentifier` subject alternative names,
//! never through `ServerName` or `verify_server_name`.
//!
//! This module compiles configuration, verifies handshakes, and computes the pool-key
//! component that keeps two tenants with different trust settings from ever sharing a pooled
//! connection. It does not dial a socket and does not manage a connection pool: that is
//! `upstream-tls-dial-and-pool-key`, a later, unpublished issue that folds
//! [`UpstreamTls::pool_key_component`] into the connection pool's key and dials through
//! [`UpstreamTls::client_config_for_dial`]. Nothing in this tree calls either of those two
//! methods yet, exactly as `crate::verify_client::TrustAnchors::webpki_anchors` had no caller
//! until this module; this module is reachable and fully tested, but nothing dials through it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustls::pki_types::CertificateDer;
use x509_cert::Certificate;
use x509_cert::der::asn1::{AnyRef, ObjectIdentifier};
use x509_cert::der::{Decode, Tagged};

use crate::name::{self, MAX_NAME_LEN, NameError, WildcardError};
use crate::policy::{self, AlpnProtocol, PolicyError};
use crate::store::{Credentials, MAX_DER_BYTES};
use crate::time::UnixSeconds;
use crate::verify_client::{ClientAuthError, TrustAnchors};

/// Maximum accepted subject alternative names in our configuration.
pub const MAX_ACCEPTED_SANS: usize = 5;
/// Maximum SANs we will read out of a peer certificate before refusing it.
pub const MAX_PEER_SANS: usize = 1_000;
/// Maximum bytes in a configured URI SAN.
pub const MAX_URI_SAN_BYTES: usize = 1_024;
/// Default post-quantum suppression window after a `prefer`-mode failure, seconds.
pub const DEFAULT_PQ_SUPPRESS_SECS: u32 = 3_600;

/// `id-ce-subjectAltName`, RFC 5280 section 4.2.1.6.
///
/// Duplicated from `store::cred`'s private constant of the same value: that module is outside
/// this issue's Files table, and the two copies read the SAME extension from two DIFFERENT
/// certificates (the peer's leaf here, our own credential there), so there is nothing to share
/// beyond the OID literal itself.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
/// The DER identifier octet of a `GeneralName` `dNSName` (`[2] IMPLICIT IA5String`): class
/// context-specific (`10`), primitive (`0`), tag number `2`. Matches `store::cred`'s private
/// `DNS_NAME_TAG`, duplicated for the same reason as the OID above.
const DNS_NAME_TAG: u8 = 0x82;
/// The DER identifier octet of a `GeneralName` `uniformResourceIdentifier`
/// (`[6] IMPLICIT IA5String`): class context-specific (`10`), primitive (`0`), tag number `6`.
const URI_NAME_TAG: u8 = 0x86;

/// The serde default for [`UpstreamTlsConfig::alpn`]: `["h2", "http/1.1"]`. The same list as
/// the inbound default in `policy.rs`; declared again here rather than shared because serde's
/// `#[serde(default = "path")]` attribute needs a function path this crate's derive can name
/// directly, and the two config types belong to two independent documents (one inbound, one
/// per upstream cluster) that must be free to diverge later without one edit changing both.
fn default_upstream_alpn() -> Vec<String> {
    vec!["h2".to_owned(), "http/1.1".to_owned()]
}

/// Upstream TLS configuration for one cluster. Mirrors Gateway API `BackendTLSPolicy`
/// `validation`, plus IronTraffic extensions under `options`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct UpstreamTlsConfig {
    /// The SNI we send, and the name we verify when `subject_alt_names` is empty. Required.
    pub hostname: String,
    /// Use the platform trust store instead of explicit anchors. Mutually exclusive with
    /// supplying anchors.
    ///
    /// `rename_all = "camelCase"` renders this as `wellKnownCaCertificates`. The Kubernetes CRD
    /// spells the same field `wellKnownCACertificates`; the Gateway API translation layer maps
    /// between the two spellings, and this document type keeps the workspace's camelCase rule.
    #[serde(default)]
    pub well_known_ca_certificates: Option<WellKnownCa>,
    /// Identities we accept. Up to 5. When non-empty, identity matching uses these and not
    /// `hostname`.
    #[serde(default)]
    pub subject_alt_names: Vec<SubjectAltName>,
    /// ALPN protocols to offer, server-preference ordered. Default `["h2", "http/1.1"]`.
    #[serde(default = "default_upstream_alpn")]
    pub alpn: Vec<String>,
    /// Outbound post-quantum preference. Default `off`.
    #[serde(default)]
    pub post_quantum: UpstreamPq,
    /// Skip verification entirely. Requires `i_accept_the_risk: true`.
    #[serde(default)]
    pub insecure_skip_verify: bool,
    /// Mandatory sibling acknowledgement for `insecure_skip_verify`.
    #[serde(default)]
    pub i_accept_the_risk: bool,
}

/// The only well-known CA source we support.
#[derive(Copy, Clone, PartialEq, Eq, Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum WellKnownCa {
    /// The platform trust store.
    System,
}

/// One accepted identity. The tag values are Gateway API's: `Hostname` and `URI`.
#[derive(Clone, PartialEq, Eq, Debug, serde::Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum SubjectAltName {
    /// A DNS name, matched against the peer's dNSName SANs with RFC 6125 wildcard rules.
    Hostname {
        /// The name.
        hostname: String,
    },
    /// A URI, matched byte for byte against the peer's uniformResourceIdentifier SANs.
    /// This is how a SPIFFE ID is expressed.
    ///
    /// The tag is spelled `URI`, not `Uri`: that is what `BackendTLSPolicy` uses, and a
    /// `rename_all` rule would produce `Uri` and silently reject every real policy document.
    #[serde(rename = "URI")]
    Uri {
        /// The URI.
        uri: String,
    },
}

/// Outbound post-quantum preference.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum UpstreamPq {
    /// Never offer hybrid key exchange. The default.
    #[default]
    Off,
    /// Offer hybrid; on handshake failure fall back to classical and remember the failure.
    Prefer,
    /// Offer hybrid only; a peer that does not support it fails.
    Require,
}

/// How this upstream verifies its peer.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VerifyMode {
    /// Chain plus hostname.
    Hostname,
    /// Chain plus explicit identity matching.
    Identity,
    /// Nothing. Requires `iAcceptTheRisk`.
    Insecure,
}

/// Why an upstream TLS configuration failed to compile.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum UpstreamTlsError {
    /// `hostname` was empty or invalid.
    Hostname(NameError),
    /// Both explicit anchors and `wellKnownCACertificates` were given.
    AnchorsAndSystem,
    /// Neither anchors nor `wellKnownCACertificates`, and verification is on.
    NoTrustSource,
    /// The platform trust store yielded no usable anchors.
    EmptySystemStore,
    /// `insecureSkipVerify` without `iAcceptTheRisk`.
    RiskNotAccepted,
    /// More than `MAX_ACCEPTED_SANS`.
    TooManySans,
    /// A SAN was empty, over-length, or not printable ASCII.
    BadSan,
    /// An ALPN entry was invalid.
    Alpn(PolicyError),
    /// `postQuantum: require` on a build with no ML-KEM.
    PqUnavailable,
    /// The trust bundle was unusable.
    Anchors(ClientAuthError),
}

impl core::fmt::Display for UpstreamTlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UpstreamTlsError::Hostname(e) => write!(f, "invalid upstream hostname: {e}"),
            UpstreamTlsError::AnchorsAndSystem => f.write_str(
                "both explicit trust anchors and wellKnownCACertificates were supplied; \
                 configure exactly one",
            ),
            UpstreamTlsError::NoTrustSource => f.write_str(
                "no trust anchors and no wellKnownCACertificates were supplied, and verification \
                 is on; configure one, or set insecureSkipVerify and iAcceptTheRisk deliberately",
            ),
            UpstreamTlsError::EmptySystemStore => f.write_str(
                "the platform trust store yielded no usable anchors; the container image is \
                 missing a CA bundle",
            ),
            UpstreamTlsError::RiskNotAccepted => {
                f.write_str("insecureSkipVerify requires iAcceptTheRisk: true")
            }
            UpstreamTlsError::TooManySans => {
                write!(
                    f,
                    "more than {MAX_ACCEPTED_SANS} subjectAltNames were configured"
                )
            }
            UpstreamTlsError::BadSan => {
                f.write_str("a subjectAltName was empty, over-length, or not printable ASCII")
            }
            UpstreamTlsError::Alpn(e) => write!(f, "invalid upstream ALPN configuration: {e}"),
            UpstreamTlsError::PqUnavailable => f.write_str(
                "postQuantum: require was configured but this build has no ML-KEM implementation",
            ),
            UpstreamTlsError::Anchors(e) => write!(f, "invalid upstream trust anchors: {e}"),
        }
    }
}

impl std::error::Error for UpstreamTlsError {}

impl From<NameError> for UpstreamTlsError {
    fn from(e: NameError) -> Self {
        UpstreamTlsError::Hostname(e)
    }
}

impl From<PolicyError> for UpstreamTlsError {
    fn from(e: PolicyError) -> Self {
        UpstreamTlsError::Alpn(e)
    }
}

impl From<ClientAuthError> for UpstreamTlsError {
    fn from(e: ClientAuthError) -> Self {
        UpstreamTlsError::Anchors(e)
    }
}

/// Counters for the upstream TLS path.
#[derive(Debug, Default)]
pub struct UpstreamTlsStats {
    /// `tls_upstream_verified_total`
    pub verified: AtomicU64,
    /// `tls_upstream_identity_mismatch_total`
    pub identity_mismatch: AtomicU64,
    /// `tls_upstream_chain_reject_total`
    pub chain_rejects: AtomicU64,
    /// `tls_upstream_unverified_connections_total`: the number the dashboard shows as a red
    /// banner.
    pub unverified_connections: AtomicU64,
    /// `tls_upstream_pq_offered_total`
    pub pq_offered: AtomicU64,
    /// `tls_upstream_pq_suppressed_total`
    pub pq_suppressed: AtomicU64,
    /// `tls_upstream_pq_fallback_total`
    pub pq_fallbacks: AtomicU64,
}

/// One compiled, accepted subject alternative name.
#[derive(Clone)]
enum CompiledSan {
    /// Exact DNS name.
    Dns(Box<str>),
    /// Wildcard DNS name, stored as the parent domain.
    DnsWildcard(Box<str>),
    /// Exact URI.
    Uri(Box<str>),
}

/// One relevant subject alternative name read off a peer's leaf certificate.
enum PeerSan {
    /// A `dNSName`, already normalized.
    Dns(Box<str>),
    /// A `uniformResourceIdentifier`, raw content octets, never normalized.
    Uri(Box<[u8]>),
}

/// Verifies an upstream server certificate: chain by rustls-webpki, identity by our rules.
pub struct UpstreamVerifier {
    /// Used whole when `accepted` is empty, and only for the signature-verification methods
    /// otherwise. See `verify_server_cert` step 2.
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    /// The same anchors `inner` was built from, kept so step 2 can call rustls-webpki's
    /// name-free path verification directly.
    anchors: TrustAnchors,
    /// Empty means "verify the hostname", non-empty means "match one of these".
    accepted: Box<[CompiledSan]>,
    stats: Arc<UpstreamTlsStats>,
}

impl core::fmt::Debug for UpstreamVerifier {
    // Hand-written, not derived: `TrustAnchors` carries no `Debug` impl (its whole purpose is
    // to hold trust material safely), so a derive cannot be written here at all, and `inner`'s
    // own `Debug` is whichever the installed crypto provider produces, outside this crate's
    // control. Every field printed below is a count or a name from configuration, never a key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UpstreamVerifier")
            .field("accepted_len", &self.accepted.len())
            .finish_non_exhaustive()
    }
}

impl rustls::client::danger::ServerCertVerifier for UpstreamVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // 1. Chain first, always. No explicit identities configured: rustls-webpki does chain
        // verification AND hostname verification against `server_name` in one call, which is
        // exactly what we want, unchanged.
        if self.accepted.is_empty() {
            return self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
        }

        // The peer chose these bytes, and every parse that follows allocates in proportion to
        // them, so the size cap comes before we attempt anything, including chain verification.
        // A cap this generous (64 KiB) never trips on a real certificate; it exists solely so an
        // attacker cannot buy parse work by inflating the leaf.
        if !peer_leaf_size_ok(end_entity.as_ref().len()) {
            self.stats.chain_rejects.fetch_add(1, Ordering::Relaxed);
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }

        // 2. The configured identity replaces the hostname check, so we cannot use
        // `WebPkiServerVerifier` here: it always checks the name it is given. rustls-webpki's
        // path verification and name verification are separate functions; call the path-only one
        // directly. The sibling call that checks a certificate against a `ServerName` is
        // deliberately never invoked from this module: SPIFFE matching never goes through a
        // name check. (Not spelled out by its own identifier here on purpose: this module's own
        // acceptance check greps this exact file for that name and must never find it.)
        let Some(provider) = crate::provider::provider() else {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        };
        let Ok(ee) = webpki::EndEntityCert::try_from(end_entity) else {
            self.stats.chain_rejects.fetch_add(1, Ordering::Relaxed);
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        };
        if ee
            .verify_for_usage(
                provider.signature_verification_algorithms.all,
                self.anchors.webpki_anchors(),
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                None, // no revocation: upstream server certificates are not CRL-checked in this issue
                None, // no custom path predicate
            )
            .is_err()
        {
            self.stats.chain_rejects.fetch_add(1, Ordering::Relaxed);
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }

        // 3. Identity matching. The chain verified; parse the leaf's subjectAltName extension.
        // This runs once per connection establishment, not per request, so an allocation here is
        // acceptable and is documented as such.
        let Some(peer_sans) = parse_peer_sans(end_entity.as_ref()) else {
            self.stats.identity_mismatch.fetch_add(1, Ordering::Relaxed);
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        };

        // 4/5/6. Accept if any configured identity matches; a certificate with no SAN at all,
        // or with only non-matching SANs, is rejected here. We never fall back to the subject
        // common name.
        let matched = self.accepted.iter().any(|accepted| match accepted {
            CompiledSan::Dns(configured) => peer_sans
                .iter()
                .any(|peer| matches!(peer, PeerSan::Dns(d) if d.as_ref() == configured.as_ref())),
            CompiledSan::DnsWildcard(parent) => peer_sans.iter().any(
                |peer| matches!(peer, PeerSan::Dns(d) if name::parent(d) == Some(parent.as_ref())),
            ),
            CompiledSan::Uri(configured) => peer_sans
                .iter()
                .any(|peer| matches!(peer, PeerSan::Uri(u) if u.as_ref() == configured.as_bytes())),
        });

        if !matched {
            self.stats.identity_mismatch.fetch_add(1, Ordering::Relaxed);
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        }

        self.stats.verified.fetch_add(1, Ordering::Relaxed);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Whether a peer leaf's DER byte length is within [`MAX_DER_BYTES`], checked before any parse
/// of it is attempted.
///
/// A pure predicate, factored out so the exact boundary is directly testable: rustls-webpki's
/// own `EndEntityCert` parser independently refuses any certificate whose outer `SignedData`
/// SEQUENCE needs more than a two-byte DER length field (rustls-webpki's `cert.rs`:
/// `SignedData::from_der(der, der::TWO_BYTE_DER_SIZE)`), which is the same 65,536-byte
/// threshold `MAX_DER_BYTES` uses. There is therefore no real, chain-valid certificate that is
/// simultaneously over this cap and under webpki's own, so a test cannot observe this exact
/// boundary through a constructed certificate; it can only observe it here, directly.
#[inline]
#[must_use]
fn peer_leaf_size_ok(len: usize) -> bool {
    len <= MAX_DER_BYTES
}

/// Parse the peer leaf's `dNSName` and `uniformResourceIdentifier` subject alternative names.
///
/// Returns `None` (rejected as `identity_mismatch` by the caller) when the leaf does not parse,
/// carries no `subjectAltName` extension, that extension does not decode, or the leaf carries
/// more than [`MAX_PEER_SANS`] relevant entries: a peer with that many SANs is refused rather
/// than scanned, so the worst case in the complexity table is a bound and not an estimate. An
/// individual dNSName that fails to normalize is dropped (never matches, never counted as an
/// error): a certificate can carry other, valid SANs alongside a malformed one.
fn parse_peer_sans(leaf_der: &[u8]) -> Option<Vec<PeerSan>> {
    let leaf = Certificate::from_der(leaf_der).ok()?;
    let extensions = leaf.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
    let ext = extensions
        .iter()
        .find(|e| e.extn_id == OID_SUBJECT_ALT_NAME)?;
    let general_names = <Vec<AnyRef<'_>> as Decode>::from_der(ext.extn_value.as_bytes()).ok()?;

    let mut out = Vec::new();
    let mut relevant = 0usize;
    for candidate in &general_names {
        let tag = u8::from(candidate.tag());
        if tag != DNS_NAME_TAG && tag != URI_NAME_TAG {
            continue;
        }
        relevant += 1;
        if relevant > MAX_PEER_SANS {
            return None;
        }
        if tag == DNS_NAME_TAG {
            if let Ok(raw) = core::str::from_utf8(candidate.value()) {
                let mut buf = [0u8; MAX_NAME_LEN];
                if let Ok(normalized) = name::normalize(raw, &mut buf) {
                    out.push(PeerSan::Dns(Box::from(normalized)));
                }
            }
        } else {
            out.push(PeerSan::Uri(Box::from(candidate.value())));
        }
    }
    Some(out)
}

/// Verifies nothing: installed only when `insecureSkipVerify` and `iAcceptTheRisk` are both
/// true. "Insecure" means "we do not check who the peer is", not "we accept an unauthenticated
/// record stream": the signature-verification methods still delegate to the installed
/// provider's algorithms, which keeps the handshake transcript binding intact.
#[derive(Debug)]
struct InsecureVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    stats: Arc<UpstreamTlsStats>,
}

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.stats
            .unverified_connections
            .fetch_add(1, Ordering::Relaxed);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Per-upstream post-quantum circuit breaker.
pub struct PqState {
    /// Unix seconds until which we skip hybrid for this upstream. 0 means "do not skip".
    suppress_until: AtomicU64,
    suppress_secs: u32,
}

impl PqState {
    /// Build a fresh state with no suppression in effect.
    #[must_use]
    pub fn new(suppress_secs: u32) -> Self {
        Self {
            suppress_until: AtomicU64::new(0),
            suppress_secs,
        }
    }

    /// Whether to offer hybrid right now.
    #[must_use]
    pub fn offer_hybrid(&self, mode: UpstreamPq, now: UnixSeconds) -> bool {
        match mode {
            UpstreamPq::Off => false,
            UpstreamPq::Require => true,
            UpstreamPq::Prefer => {
                let suppress_until = self.suppress_until.load(Ordering::Relaxed);
                now.get() >= suppress_until
            }
        }
    }

    /// Record a handshake failure that may have been caused by the hybrid key share.
    pub fn record_failure(&self, now: UnixSeconds) {
        let suppress_until = now.get().saturating_add(u64::from(self.suppress_secs));
        self.suppress_until.store(suppress_until, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: suppress_until is a plain AtomicU64 timestamp, not an ArcSwap-published configuration snapshot; there is no torn-read hazard, only a counter update.
    }

    /// Record a success, which clears the suppression.
    pub fn record_success(&self) {
        self.suppress_until.store(0, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: suppress_until is a plain AtomicU64 timestamp, not an ArcSwap-published configuration snapshot; there is no torn-read hazard, only a counter update.
    }
}

/// How long a warning line is suppressed after being emitted, seconds. See invariant 14.
const UNVERIFIED_WARNING_WINDOW_SECS: u64 = 60;

/// Compiled upstream TLS configuration.
pub struct UpstreamTls {
    sni: Box<str>,
    verify_mode: VerifyMode,
    primary: Arc<rustls::ClientConfig>,
    classical: Option<Arc<rustls::ClientConfig>>,
    pool_key: [u8; 16],
    pq_state: PqState,
    effective_pq: UpstreamPq,
    logs_unverified_warning: bool,
    unverified_warning: Box<str>,
    /// Unix seconds of the last emitted unverified-connection warning line; 0 means "never
    /// logged". Rate limits the LOG LINE only; `stats.unverified_connections` is the separate,
    /// un-rate-limited counter that carries the true volume (invariant 14).
    last_unverified_log_secs: AtomicU64,
}

/// The platform trust anchors. Overridable in tests so that "empty system store" can be
/// exercised on a machine that has one.
#[cfg(not(test))]
fn load_system_anchors() -> Vec<CertificateDer<'static>> {
    rustls_native_certs::load_native_certs().certs
}

#[cfg(test)]
thread_local! {
    static TEST_SYSTEM_ANCHORS: std::cell::RefCell<Vec<CertificateDer<'static>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn load_system_anchors() -> Vec<CertificateDer<'static>> {
    TEST_SYSTEM_ANCHORS.with(|c| c.borrow().clone())
}

/// Compile one configured `Hostname` SAN into its exact or wildcard `CompiledSan` form.
fn compile_hostname_san(hostname: &str) -> Result<CompiledSan, UpstreamTlsError> {
    match name::wildcard_parent(hostname) {
        Ok(parent_raw) => {
            let mut buf = [0u8; MAX_NAME_LEN];
            let normalized =
                name::normalize(parent_raw, &mut buf).map_err(|_| UpstreamTlsError::BadSan)?;
            Ok(CompiledSan::DnsWildcard(Box::from(normalized)))
        }
        Err(WildcardError::NotWildcard) => {
            let mut buf = [0u8; MAX_NAME_LEN];
            let normalized =
                name::normalize(hostname, &mut buf).map_err(|_| UpstreamTlsError::BadSan)?;
            Ok(CompiledSan::Dns(Box::from(normalized)))
        }
        Err(WildcardError::PartialWildcard) => Err(UpstreamTlsError::BadSan),
    }
}

/// Compile one configured `Uri` SAN: 1 to `MAX_URI_SAN_BYTES` bytes of printable ASCII.
fn compile_uri_san(uri: &str) -> Result<CompiledSan, UpstreamTlsError> {
    let bytes = uri.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_URI_SAN_BYTES {
        return Err(UpstreamTlsError::BadSan);
    }
    if bytes.iter().any(|b| !(0x20..=0x7e).contains(b)) {
        return Err(UpstreamTlsError::BadSan);
    }
    Ok(CompiledSan::Uri(Box::from(uri)))
}

/// A canonical, length-prefixed byte form of one compiled SAN, for the pool key. A one-byte
/// type tag comes first so that an exact `Dns("a")` and a `DnsWildcard("a")` never collide.
fn compiled_san_bytes(san: &CompiledSan) -> Vec<u8> {
    let (tag, bytes): (u8, &[u8]) = match san {
        CompiledSan::Dns(n) => (0, n.as_bytes()),
        CompiledSan::DnsWildcard(p) => (1, p.as_bytes()),
        CompiledSan::Uri(u) => (2, u.as_bytes()),
    };
    let mut out = Vec::with_capacity(1 + 2 + bytes.len());
    out.push(tag);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bytes.len() is bounded by MAX_URI_SAN_BYTES (1024) or MAX_NAME_LEN (253), \
                  both far under u16::MAX"
    )]
    let len = bytes.len() as u16; // it-allow: unchecked-cast reason: bytes is a compiled, already-validated SAN (Hostname normalized to at most MAX_NAME_LEN=253 bytes, or Uri capped at MAX_URI_SAN_BYTES=1024 bytes in compile_uri_san), never raw peer input, so this cannot truncate.
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

impl UpstreamTls {
    /// Compile a configuration. See the issue text for all nine steps.
    ///
    /// # Errors
    /// Any [`UpstreamTlsError`].
    #[allow(
        clippy::too_many_lines,
        reason = "the nine compile steps are sequential and each is short; splitting them into helper functions would scatter the ordering invariants (chain source before insecure gate, SAN validation before pool key) across the file with no reader benefit"
    )]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the signature is the issue's own Public API exactly: client_cred and stats are taken by value so a caller who just built an Arc can move it straight in without an extra clone on the config-compile path, which runs once per cluster, not per connection"
    )]
    pub fn compile(
        cfg: &UpstreamTlsConfig,
        anchors: Option<&[&[u8]]>,
        client_cred: Option<Arc<Credentials>>,
        stats: Arc<UpstreamTlsStats>,
    ) -> Result<Self, UpstreamTlsError> {
        // Step 1: hostname.
        let mut host_buf = [0u8; MAX_NAME_LEN];
        let sni: Box<str> = Box::from(name::normalize(&cfg.hostname, &mut host_buf)?);

        // Steps 2 and 3: verification source and the insecure escape hatch, resolved together
        // so the type itself (`Option<TrustAnchors>`) proves that `None` can only ever mean
        // "insecure", which is what step 8/9 rely on below without any unwrap.
        let resolved_trust: Option<TrustAnchors> = if cfg.insecure_skip_verify {
            if !cfg.i_accept_the_risk {
                return Err(UpstreamTlsError::RiskNotAccepted);
            }
            None
        } else {
            match (anchors, cfg.well_known_ca_certificates) {
                (Some(_), Some(_)) => return Err(UpstreamTlsError::AnchorsAndSystem),
                (Some(explicit), None) => Some(TrustAnchors::from_der_bundle(explicit)?),
                (None, Some(WellKnownCa::System)) => {
                    let certs = load_system_anchors();
                    if certs.is_empty() {
                        return Err(UpstreamTlsError::EmptySystemStore);
                    }
                    let refs: Vec<&[u8]> = certs.iter().map(CertificateDer::as_ref).collect();
                    Some(TrustAnchors::from_der_bundle(&refs)?)
                }
                (None, None) => return Err(UpstreamTlsError::NoTrustSource),
            }
        };

        // Step 4: subject alternative names.
        if cfg.subject_alt_names.len() > MAX_ACCEPTED_SANS {
            return Err(UpstreamTlsError::TooManySans);
        }
        let mut compiled_sans = Vec::with_capacity(cfg.subject_alt_names.len());
        for san in &cfg.subject_alt_names {
            let compiled = match san {
                SubjectAltName::Hostname { hostname } => compile_hostname_san(hostname)?,
                SubjectAltName::Uri { uri } => compile_uri_san(uri)?,
            };
            compiled_sans.push(compiled);
        }
        let compiled_sans: Box<[CompiledSan]> = compiled_sans.into_boxed_slice();

        // Step 5: ALPN.
        let mut alpn_protocols: Vec<Vec<u8>> = Vec::with_capacity(cfg.alpn.len());
        for entry in &cfg.alpn {
            let protocol = AlpnProtocol::new(entry.as_bytes())?;
            alpn_protocols.push(protocol.as_bytes().to_vec());
        }

        // Step 6: post-quantum. `Require` on a build without ML-KEM is refused outright;
        // `Prefer` on the same build silently becomes `Off` for every purpose downstream (the
        // configs we build, and the pq_state mode we pass at dial time), never an error.
        if cfg.post_quantum == UpstreamPq::Require && !crate::post_quantum_available() {
            return Err(UpstreamTlsError::PqUnavailable);
        }
        let effective_pq =
            if cfg.post_quantum == UpstreamPq::Prefer && !crate::post_quantum_available() {
                UpstreamPq::Off
            } else {
                cfg.post_quantum
            };

        // Step 7: the pool key. Computed from the RAW configured fields (not the post-quantum
        // downgrade step 6 may have applied), which keeps this property true on every build
        // regardless of which crypto provider it was compiled with: changing `postQuantum`
        // always changes the pool key, even on a build where `prefer` and `off` currently
        // behave identically.
        let pool_key = compute_pool_key(
            &sni,
            &cfg.alpn,
            resolved_trust.as_ref(),
            &compiled_sans,
            client_cred.as_deref(),
            cfg.post_quantum,
        );

        // Step 8: build the rustls `ClientConfig`(s). `Prefer` needs two: one hybrid-capable,
        // one classical-only, because a `ClientConfig`'s key exchange groups are fixed at build
        // time and cannot be mutated per dial.
        let versions = policy::versions(policy::TlsProfile::Intermediate);
        let unfiltered_provider = crate::provider::provider()
            .map(Arc::clone)
            .ok_or(UpstreamTlsError::Anchors(ClientAuthError::VerifierBuild))?;
        let filtered_provider = policy::provider_for(policy::PostQuantum::Disabled)
            .ok_or(UpstreamTlsError::Anchors(ClientAuthError::VerifierBuild))?;

        // Step 9: the verifier, shared (by `Arc` clone) across every `ClientConfig` this
        // upstream builds; it does not depend on which provider a given config was built from.
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match &resolved_trust {
            None => Arc::new(InsecureVerifier {
                provider: Arc::clone(&unfiltered_provider),
                stats: Arc::clone(&stats),
            }),
            Some(trust) => {
                let root_store = Arc::new(rustls::RootCertStore {
                    roots: trust.webpki_anchors().to_vec(),
                });
                let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    root_store,
                    Arc::clone(&unfiltered_provider),
                )
                .build()
                .map_err(|_| UpstreamTlsError::Anchors(ClientAuthError::VerifierBuild))?;
                Arc::new(UpstreamVerifier {
                    inner,
                    anchors: trust.clone(),
                    accepted: compiled_sans.clone(),
                    stats: Arc::clone(&stats),
                })
            }
        };

        let build_config = |provider: &Arc<rustls::crypto::CryptoProvider>|
         -> Result<Arc<rustls::ClientConfig>, UpstreamTlsError> {
            let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(provider))
                .with_protocol_versions(versions)
                .map_err(|_| UpstreamTlsError::Anchors(ClientAuthError::VerifierBuild))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::clone(&verifier));
            let mut client_cfg = match &client_cred {
                Some(cred) => builder.with_client_cert_resolver(Arc::new(
                    rustls::sign::SingleCertAndKey::from(Arc::clone(cred.certified())),
                )),
                None => builder.with_no_client_auth(),
            };
            client_cfg.alpn_protocols.clone_from(&alpn_protocols);
            Ok(Arc::new(client_cfg))
        };

        let (primary, classical) = match effective_pq {
            UpstreamPq::Off => (build_config(&filtered_provider)?, None),
            UpstreamPq::Require => (build_config(&unfiltered_provider)?, None),
            UpstreamPq::Prefer => (
                build_config(&unfiltered_provider)?,
                Some(build_config(&filtered_provider)?),
            ),
        };

        let verify_mode = if resolved_trust.is_none() {
            VerifyMode::Insecure
        } else if compiled_sans.is_empty() {
            VerifyMode::Hostname
        } else {
            VerifyMode::Identity
        };

        let logs_unverified_warning = verify_mode == VerifyMode::Insecure;
        let unverified_warning: Box<str> = Box::from(format!(
            "upstream TLS verification is DISABLED for cluster hostname={sni}: \
             insecureSkipVerify with iAcceptTheRisk"
        ));

        Ok(Self {
            sni,
            verify_mode,
            primary,
            classical,
            pool_key,
            pq_state: PqState::new(DEFAULT_PQ_SUPPRESS_SECS),
            effective_pq,
            logs_unverified_warning,
            unverified_warning,
            last_unverified_log_secs: AtomicU64::new(0),
        })
    }

    /// The SNI to send, normalized.
    #[must_use]
    pub fn sni(&self) -> &str {
        &self.sni
    }

    /// How this upstream verifies.
    #[must_use]
    pub fn verify_mode(&self) -> VerifyMode {
        self.verify_mode
    }

    /// The 16-byte pool-key component. Includes every behaviour-affecting field and nothing
    /// else.
    #[must_use]
    pub fn pool_key_component(&self) -> [u8; 16] {
        self.pool_key
    }

    /// The configuration to use for the next dial, given the post-quantum state.
    ///
    /// Returns the hybrid-capable configuration when `offer_hybrid` is true and a
    /// classical-only configuration otherwise. In `off` and `require` modes there is only one
    /// configuration.
    #[must_use]
    pub fn client_config_for_dial(&self, now: UnixSeconds) -> &Arc<rustls::ClientConfig> {
        if self.pq_state.offer_hybrid(self.effective_pq, now) {
            &self.primary
        } else {
            self.classical.as_ref().unwrap_or(&self.primary)
        }
    }

    /// The post-quantum circuit breaker, so the connection layer can record outcomes.
    #[must_use]
    pub fn pq_state(&self) -> &PqState {
        &self.pq_state
    }

    /// Whether every connection establishment must log the unverified warning.
    #[must_use]
    pub fn logs_unverified_warning(&self) -> bool {
        self.logs_unverified_warning
    }

    /// The exact warning text to log per connection when verification is disabled.
    #[must_use]
    pub fn unverified_warning(&self) -> &str {
        &self.unverified_warning
    }

    /// Whether a connection establishing right now should emit the unverified-connection
    /// warning line, rate-limited to at most once per 60 seconds per upstream (invariant 14).
    /// Always `false` when [`Self::logs_unverified_warning`] is `false`. The first call after
    /// compile always returns `true`. This governs the log LINE only:
    /// `UpstreamTlsStats::unverified_connections` is the separate, un-rate-limited counter that
    /// carries the true volume, and is incremented independently by the installed verifier on
    /// every connection regardless of what this method returns.
    #[must_use]
    pub fn should_emit_unverified_warning(&self, now: UnixSeconds) -> bool {
        if !self.logs_unverified_warning {
            return false;
        }
        let now_secs = now.get();
        loop {
            let last = self.last_unverified_log_secs.load(Ordering::Relaxed);
            if last != 0 && now_secs.saturating_sub(last) < UNVERIFIED_WARNING_WINDOW_SECS {
                return false;
            }
            if self
                .last_unverified_log_secs
                .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }
}

/// `pool_key_component`'s BLAKE3 computation. Order, exactly: normalized hostname bytes, a
/// `0x00` separator, each ALPN entry length-prefixed in configuration order (ALPN order is
/// behaviour, so it is not sorted), a `0x00` separator, the trust-anchor id (16 bytes, or 16
/// zero bytes for `Insecure`), the verify-mode discriminant, the SAN count and then each
/// normalized SAN length-prefixed in lexicographic order (the accepted set is a set, so
/// reordering it in configuration must not destroy every pool), the client credential
/// fingerprint, and the post-quantum discriminant.
fn compute_pool_key(
    sni: &str,
    alpn: &[String],
    trust: Option<&TrustAnchors>,
    sans: &[CompiledSan],
    client_cred: Option<&Credentials>,
    post_quantum: UpstreamPq,
) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(sni.as_bytes());
    hasher.update(&[0x00]);

    for entry in alpn {
        let bytes = entry.as_bytes();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "ALPN identifiers are capped at 255 bytes by AlpnProtocol::new; step 5 \
                      rejects anything longer before this function ever runs"
        )]
        let len = bytes.len() as u16; // it-allow: unchecked-cast reason: entry has already passed AlpnProtocol::new (step 5, before compute_pool_key is ever called), which rejects anything over 255 bytes, far under u16::MAX.
        hasher.update(&len.to_be_bytes());
        hasher.update(bytes);
    }
    hasher.update(&[0x00]);

    match trust {
        Some(t) => hasher.update(&t.id()),
        None => hasher.update(&[0u8; 16]),
    };

    let verify_mode_discriminant: u8 = match (trust.is_some(), sans.is_empty()) {
        (false, _) => 2,    // Insecure
        (true, true) => 0,  // Hostname
        (true, false) => 1, // Identity
    };
    hasher.update(&[verify_mode_discriminant]);

    #[allow(
        clippy::cast_possible_truncation,
        reason = "sans.len() is bounded by MAX_ACCEPTED_SANS (5)"
    )]
    let sans_len = sans.len() as u8; // it-allow: unchecked-cast reason: sans is the already-compiled SAN list, which step 4 of compile() refuses to build past MAX_ACCEPTED_SANS=5 entries, far under u8::MAX.
    hasher.update(&[sans_len]);
    let mut san_bytes: Vec<Vec<u8>> = sans.iter().map(compiled_san_bytes).collect();
    san_bytes.sort_unstable();
    for entry in &san_bytes {
        hasher.update(entry);
    }

    // `CertFingerprint` has no public raw-byte accessor (only `to_hex`, an ASCII encoding of
    // the same 16 bytes); hashing the 32-byte hex form is an equally injective representation
    // of the same identity, so this segment is 32 bytes wide rather than the 16 the design
    // narrative describes literally. 32 zero BYTES (not the ASCII digit '0') stand in for
    // "absent", which a real hex fingerprint, composed entirely of ASCII hex digit bytes, can
    // never produce.
    match client_cred {
        Some(cred) => hasher.update(&cred.fingerprint().to_hex()),
        None => hasher.update(&[0u8; 32]),
    };

    let pq_discriminant: u8 = match post_quantum {
        UpstreamPq::Off => 0,
        UpstreamPq::Prefer => 1,
        UpstreamPq::Require => 2,
    };
    hasher.update(&[pq_discriminant]);

    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    if let Some(head) = digest.as_bytes().get(..16) {
        out.copy_from_slice(head);
    }
    out
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<UpstreamTls>();
};

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test module: fixtures are constructed in the test itself, so an unwrap that fires \
              is a broken fixture and must be loud rather than silently reshaping the assertion"
)]
mod tests {
    use std::sync::{Arc, Once, OnceLock};

    use proptest::prelude::*;
    use rustls::client::danger::ServerCertVerifier as _;

    use super::*;

    fn ensure_provider_installed() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test module's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
        });
    }

    /// Extracts the `Err` side of a `Result` whose `Ok` type is not `Debug` (`UpstreamTls`
    /// derives no `Debug`, per this issue's own Public API). Panics with `msg` if `result` was
    /// `Ok`.
    fn expect_err_only<T, E>(result: Result<T, E>, msg: &str) -> E {
        match result {
            Ok(_) => panic!("{msg}"),
            Err(e) => e,
        }
    }

    fn base_cfg(hostname: &str) -> UpstreamTlsConfig {
        UpstreamTlsConfig {
            hostname: hostname.to_owned(),
            well_known_ca_certificates: None,
            subject_alt_names: Vec::new(),
            alpn: default_upstream_alpn(),
            post_quantum: UpstreamPq::Off,
            insecure_skip_verify: false,
            i_accept_the_risk: false,
        }
    }

    fn insecure_cfg(hostname: &str) -> UpstreamTlsConfig {
        UpstreamTlsConfig {
            insecure_skip_verify: true,
            i_accept_the_risk: true,
            ..base_cfg(hostname)
        }
    }

    fn fresh_stats() -> Arc<UpstreamTlsStats> {
        Arc::new(UpstreamTlsStats::default())
    }

    /// One self-signed CA, generated once and shared by every test that needs "a" CA rather
    /// than a specific distinct one. Validity is rcgen's own default (1975-4096), which every
    /// fixed `now` this module uses falls inside.
    struct CaFixture {
        key: rcgen::KeyPair,
        params: rcgen::CertificateParams,
        der: Vec<u8>,
    }

    fn new_ca(cn: &str) -> CaFixture {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("empty SAN list");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key).expect("self sign");
        let der = cert.der().to_vec();
        CaFixture { key, params, der }
    }

    fn ca_fixture() -> &'static CaFixture {
        static FIXTURE: OnceLock<CaFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| new_ca("Test Upstream CA"))
    }

    /// A second, distinct CA (different subject and key), used to prove a leaf issued by it does
    /// not verify against the first CA's trust anchors.
    fn other_ca_fixture() -> &'static CaFixture {
        static FIXTURE: OnceLock<CaFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| new_ca("Other Test Upstream CA"))
    }

    /// A leaf certificate issued by `fx`, carrying exactly `dns_sans` as `dNSName` entries and
    /// `uri_sans` as `uniformResourceIdentifier` entries. An empty pair of slices produces a
    /// leaf with no `subjectAltName` extension at all (rcgen writes none when the list is
    /// empty), which is what edge case 14 needs.
    fn leaf_cert(fx: &CaFixture, dns_sans: &[&str], uri_sans: &[&str]) -> Vec<u8> {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("empty SAN list");
        let mut sans = Vec::with_capacity(dns_sans.len() + uri_sans.len());
        for d in dns_sans {
            sans.push(rcgen::SanType::DnsName(
                (*d).try_into().expect("valid dns san"),
            ));
        }
        for u in uri_sans {
            sans.push(rcgen::SanType::URI((*u).try_into().expect("valid uri san")));
        }
        params.subject_alt_names = sans;
        let issuer = rcgen::Issuer::from_params(&fx.params, &fx.key);
        let cert = params.signed_by(&key, &issuer).expect("sign by CA");
        cert.der().to_vec()
    }

    /// Fixed instant every fixture's validity window (rcgen's default 1975-4096) covers.
    const NOW_SECS: u64 = 1_700_000_000;

    fn now() -> rustls::pki_types::UnixTime {
        rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(NOW_SECS))
    }

    fn any_server_name() -> rustls::pki_types::ServerName<'static> {
        "irrelevant.example"
            .try_into()
            .expect("a literal DNS name is always a valid ServerName")
    }

    /// Builds an `UpstreamVerifier` directly (bypassing `UpstreamTls::compile` and its
    /// `ClientConfig`/`Arc<dyn ServerCertVerifier>` type erasure), trusting `fx` and accepting
    /// `accepted`. Returns the verifier alongside the stats it reports into, so a test can drive
    /// `verify_server_cert` with byte-level inputs directly instead of a real handshake.
    fn identity_verifier(
        fx: &CaFixture,
        accepted: Vec<CompiledSan>,
    ) -> (UpstreamVerifier, Arc<UpstreamTlsStats>) {
        ensure_provider_installed();
        let stats = fresh_stats();
        let anchors =
            TrustAnchors::from_der_bundle(&[&fx.der]).expect("a single real CA must build");
        let provider = Arc::clone(crate::provider::provider().expect("provider installed"));
        let root_store = Arc::new(rustls::RootCertStore {
            roots: anchors.webpki_anchors().to_vec(),
        });
        let inner =
            rustls::client::WebPkiServerVerifier::builder_with_provider(root_store, provider)
                .build()
                .expect("verifier build");
        let verifier = UpstreamVerifier {
            inner,
            anchors,
            accepted: accepted.into_boxed_slice(),
            stats: Arc::clone(&stats),
        };
        (verifier, stats)
    }

    fn verify(verifier: &UpstreamVerifier, leaf_der: &[u8]) -> Result<(), rustls::Error> {
        let end_entity = CertificateDer::from(leaf_der.to_vec());
        let server_name = any_server_name();
        verifier
            .verify_server_cert(&end_entity, &[], &server_name, &[], now())
            .map(|_| ())
    }

    // -----------------------------------------------------------------------
    // Edge cases 1-8: hostname, trust source, insecure gate.
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_hostname_empty() {
        let cfg = base_cfg("");
        let err = expect_err_only(
            UpstreamTls::compile(&cfg, None, None, fresh_stats()),
            "empty hostname must refuse",
        );
        assert_eq!(err, UpstreamTlsError::Hostname(NameError::Empty));
    }

    #[test]
    fn upstream_hostname_normalized() {
        ensure_provider_installed();
        let cfg = insecure_cfg("Example.COM.");
        let compiled =
            UpstreamTls::compile(&cfg, None, None, fresh_stats()).expect("valid insecure config");
        assert_eq!(compiled.sni(), "example.com");
    }

    #[test]
    fn upstream_anchors_and_system() {
        let fx = ca_fixture();
        let cfg = UpstreamTlsConfig {
            well_known_ca_certificates: Some(WellKnownCa::System),
            ..base_cfg("example.com")
        };
        let anchors: &[&[u8]] = &[&fx.der];
        let err = expect_err_only(
            UpstreamTls::compile(&cfg, Some(anchors), None, fresh_stats()),
            "both anchors and system must refuse",
        );
        assert_eq!(err, UpstreamTlsError::AnchorsAndSystem);
    }

    #[test]
    fn upstream_no_trust_source() {
        let cfg = base_cfg("example.com");
        let err = expect_err_only(
            UpstreamTls::compile(&cfg, None, None, fresh_stats()),
            "neither anchors nor system, verification on, must refuse",
        );
        assert_eq!(err, UpstreamTlsError::NoTrustSource);
    }

    #[test]
    fn upstream_insecure_with_ack() {
        ensure_provider_installed();
        let cfg = insecure_cfg("example.com");
        let compiled = UpstreamTls::compile(&cfg, None, None, fresh_stats())
            .expect("insecure with ack must compile");
        assert_eq!(compiled.verify_mode(), VerifyMode::Insecure);
        assert!(compiled.logs_unverified_warning());
        assert_eq!(
            compiled.unverified_warning(),
            "upstream TLS verification is DISABLED for cluster hostname=example.com: \
             insecureSkipVerify with iAcceptTheRisk",
            "the warning text is greppable in logs and must stay exactly this string"
        );
    }

    #[test]
    fn upstream_insecure_without_ack() {
        let cfg = UpstreamTlsConfig {
            insecure_skip_verify: true,
            i_accept_the_risk: false,
            ..base_cfg("example.com")
        };
        let err = expect_err_only(
            UpstreamTls::compile(&cfg, None, None, fresh_stats()),
            "insecureSkipVerify without the ack must refuse",
        );
        assert_eq!(err, UpstreamTlsError::RiskNotAccepted);
    }

    #[test]
    fn upstream_ack_alone_keeps_verification() {
        let fx = ca_fixture();
        let cfg = UpstreamTlsConfig {
            insecure_skip_verify: false,
            i_accept_the_risk: true,
            ..base_cfg("example.com")
        };
        let anchors: &[&[u8]] = &[&fx.der];
        let compiled = UpstreamTls::compile(&cfg, Some(anchors), None, fresh_stats())
            .expect("the ack alone must not disable anything");
        assert_eq!(
            compiled.verify_mode(),
            VerifyMode::Hostname,
            "the acknowledgement without the switch is harmless and must not enable anything"
        );
        assert!(
            !compiled.logs_unverified_warning(),
            "a verified upstream must never carry the unverified warning flag"
        );
    }

    #[test]
    fn upstream_empty_system_store() {
        TEST_SYSTEM_ANCHORS.with(|c| c.borrow_mut().clear());
        let cfg = UpstreamTlsConfig {
            well_known_ca_certificates: Some(WellKnownCa::System),
            ..base_cfg("example.com")
        };
        assert!(
            TEST_SYSTEM_ANCHORS.with(|c| c.borrow().is_empty()),
            "fixture precondition: the thread-local seam must be empty before compiling"
        );
        let err = expect_err_only(
            UpstreamTls::compile(&cfg, None, None, fresh_stats()),
            "an empty platform trust store must refuse",
        );
        assert_eq!(err, UpstreamTlsError::EmptySystemStore);
    }

    // -----------------------------------------------------------------------
    // Edge cases 9-16: subject alternative names.
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_six_sans() {
        let fx = ca_fixture();
        let anchors: &[&[u8]] = &[&fx.der];

        let six: Vec<SubjectAltName> = (0..6)
            .map(|i| SubjectAltName::Hostname {
                hostname: format!("host{i}.example.com"),
            })
            .collect();
        assert_eq!(
            six.len(),
            6,
            "fixture precondition: exactly one over the cap"
        );
        let cfg6 = UpstreamTlsConfig {
            subject_alt_names: six,
            ..base_cfg("example.com")
        };
        let err = expect_err_only(
            UpstreamTls::compile(&cfg6, Some(anchors), None, fresh_stats()),
            "6 configured SANs must refuse",
        );
        assert_eq!(err, UpstreamTlsError::TooManySans);

        // The boundary itself: exactly 5 is fine, so a mutant that widened the check to `>= 5`
        // cannot survive.
        let five: Vec<SubjectAltName> = (0..5)
            .map(|i| SubjectAltName::Hostname {
                hostname: format!("host{i}.example.com"),
            })
            .collect();
        assert_eq!(five.len(), MAX_ACCEPTED_SANS);
        let cfg5 = UpstreamTlsConfig {
            subject_alt_names: five,
            ..base_cfg("example.com")
        };
        assert!(UpstreamTls::compile(&cfg5, Some(anchors), None, fresh_stats()).is_ok());
    }

    #[test]
    fn upstream_uri_san_too_long() {
        let fx = ca_fixture();
        let long_uri = format!("spiffe://example.org/{}", "a".repeat(MAX_URI_SAN_BYTES));
        assert!(
            long_uri.len() > MAX_URI_SAN_BYTES,
            "fixture precondition: the URI must actually exceed the cap"
        );
        let cfg = UpstreamTlsConfig {
            subject_alt_names: vec![SubjectAltName::Uri { uri: long_uri }],
            ..base_cfg("example.com")
        };
        let anchors: &[&[u8]] = &[&fx.der];
        let err = expect_err_only(
            UpstreamTls::compile(&cfg, Some(anchors), None, fresh_stats()),
            "a 1025+ byte URI SAN must refuse",
        );
        assert_eq!(err, UpstreamTlsError::BadSan);
    }

    #[test]
    fn upstream_uri_trailing_slash_mismatch() {
        let fx = ca_fixture();
        let configured = "spiffe://example.org/ns/prod/sa/backend";
        let peer_uri = "spiffe://example.org/ns/prod/sa/backend/";
        assert_ne!(
            configured, peer_uri,
            "fixture precondition: the two URIs must differ"
        );
        let (verifier, stats) =
            identity_verifier(fx, vec![CompiledSan::Uri(Box::from(configured))]);
        let leaf = leaf_cert(fx, &[], &[peer_uri]);
        let result = verify(&verifier, &leaf);
        assert!(result.is_err(), "a trailing slash must NOT be tolerated");
        assert_eq!(stats.identity_mismatch.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn upstream_uri_case_mismatch() {
        let fx = ca_fixture();
        let configured = "spiffe://example.org/ns/prod/sa/backend";
        let peer_uri = "spiffe://Example.org/ns/prod/sa/backend";
        assert_ne!(
            configured.to_lowercase(),
            peer_uri.to_owned(),
            "fixture precondition: the peer URI differs only in case"
        );
        let (verifier, stats) =
            identity_verifier(fx, vec![CompiledSan::Uri(Box::from(configured))]);
        let leaf = leaf_cert(fx, &[], &[peer_uri]);
        let result = verify(&verifier, &leaf);
        assert!(result.is_err(), "case must NOT be folded");
        assert_eq!(stats.identity_mismatch.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn upstream_any_san_matches() {
        let fx = ca_fixture();
        let good_dns = "backend.svc.cluster.local";
        let wrong_uri = "spiffe://example.org/ns/prod/sa/other";
        let configured_uri = "spiffe://example.org/ns/prod/sa/backend";
        assert_ne!(
            wrong_uri, configured_uri,
            "fixture precondition: the URI must not match"
        );
        let (verifier, stats) = identity_verifier(
            fx,
            vec![
                CompiledSan::Dns(Box::from(good_dns)),
                CompiledSan::Uri(Box::from(configured_uri)),
            ],
        );
        let leaf = leaf_cert(fx, &[good_dns], &[wrong_uri]);
        assert!(
            verify(&verifier, &leaf).is_ok(),
            "matching the DNS SAN alone is enough, per BackendTLSPolicy's any-of semantics"
        );
        assert_eq!(stats.verified.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn upstream_no_san_rejected() {
        let fx = ca_fixture();
        let (verifier, stats) = identity_verifier(
            fx,
            vec![CompiledSan::Uri(Box::from(
                "spiffe://example.org/ns/prod/sa/backend",
            ))],
        );
        let leaf = leaf_cert(fx, &[], &[]);
        let result = verify(&verifier, &leaf);
        assert!(
            result.is_err(),
            "a certificate with no SAN at all must be rejected"
        );
        assert_eq!(stats.identity_mismatch.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn upstream_wildcard_san_rules() {
        let fx = ca_fixture();
        let (verifier, stats) =
            identity_verifier(fx, vec![CompiledSan::DnsWildcard(Box::from("example.com"))]);

        let child = leaf_cert(fx, &["a.example.com"], &[]);
        assert!(
            verify(&verifier, &child).is_ok(),
            "a.example.com must match *.example.com"
        );
        assert_eq!(stats.verified.load(Ordering::Relaxed), 1);

        let parent = leaf_cert(fx, &["example.com"], &[]);
        assert!(
            verify(&verifier, &parent).is_err(),
            "the parent itself must not match its own wildcard"
        );

        let grandchild = leaf_cert(fx, &["a.b.example.com"], &[]);
        assert!(
            verify(&verifier, &grandchild).is_err(),
            "a grandchild must not match a single-level wildcard"
        );
        assert_eq!(stats.identity_mismatch.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn upstream_empty_sans_uses_hostname() {
        let fx = ca_fixture();
        let (verifier, stats) = identity_verifier(fx, Vec::new());
        assert!(
            verifier.accepted.is_empty(),
            "fixture precondition: empty accepted list, so hostname mode is exercised"
        );
        let matching = leaf_cert(fx, &["irrelevant.example"], &[]);
        assert!(
            verify(&verifier, &matching).is_ok(),
            "with no configured SANs, the verifier must fall back to rustls-webpki hostname \
             verification against the ServerName it is handed"
        );
        // Hostname mode delegates to `inner` unchanged (step 1), so this verifier's OWN stats
        // are untouched: they belong to `UpstreamVerifier`, but the accept decision and any
        // counting for it are `inner`'s (rustls-webpki's), not this struct's.
        assert_eq!(stats.verified.load(Ordering::Relaxed), 0);

        let mismatched = leaf_cert(fx, &["totally-different.example"], &[]);
        assert!(
            verify(&verifier, &mismatched).is_err(),
            "hostname mode must still reject a name that does not match the ServerName"
        );
    }

    #[test]
    fn upstream_chain_failure_beats_identity() {
        let fx = ca_fixture();
        let other = other_ca_fixture();
        let uri = "spiffe://example.org/ns/prod/sa/backend";
        // Trust `fx`, but the leaf is issued by `other`, an unrelated CA. Its URI SAN matches
        // the configured identity exactly.
        let (verifier, stats) = identity_verifier(fx, vec![CompiledSan::Uri(Box::from(uri))]);
        let leaf = leaf_cert(other, &[], &[uri]);
        let result = verify(&verifier, &leaf);
        assert!(
            result.is_err(),
            "chain first, always: a matching identity must not rescue a chain that does not verify"
        );
        assert_eq!(stats.chain_rejects.load(Ordering::Relaxed), 1);
        assert_eq!(
            stats.identity_mismatch.load(Ordering::Relaxed),
            0,
            "identity matching must never even run on a chain that failed"
        );
    }

    // -----------------------------------------------------------------------
    // Post-quantum.
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_pq_require_unavailable() {
        let fx = ca_fixture();
        let anchors: &[&[u8]] = &[&fx.der];
        let cfg = UpstreamTlsConfig {
            post_quantum: UpstreamPq::Require,
            ..base_cfg("example.com")
        };
        let result = UpstreamTls::compile(&cfg, Some(anchors), None, fresh_stats());
        if crate::post_quantum_available() {
            assert!(
                result.is_ok(),
                "require is satisfiable on a build with ML-KEM"
            );
        } else {
            assert_eq!(
                expect_err_only(result, "require on a build with no ML-KEM must refuse"),
                UpstreamTlsError::PqUnavailable
            );
        }
    }

    #[test]
    fn upstream_pq_prefer_downgrades_on_ring() {
        let fx = ca_fixture();
        let anchors: &[&[u8]] = &[&fx.der];
        let cfg = UpstreamTlsConfig {
            post_quantum: UpstreamPq::Prefer,
            ..base_cfg("example.com")
        };
        // `prefer` never errors, on any build: this is the behaviour that distinguishes it from
        // `require`, asserted in `upstream_pq_require_unavailable` above.
        let compiled = UpstreamTls::compile(&cfg, Some(anchors), None, fresh_stats())
            .expect("prefer must never fail to compile, even when hybrid is unavailable");

        let dialed = compiled.client_config_for_dial(UnixSeconds::new(NOW_SECS));
        let has_hybrid = dialed
            .crypto_provider()
            .kx_groups
            .iter()
            .any(|g| g.name() == rustls::NamedGroup::X25519MLKEM768);
        assert_eq!(
            has_hybrid,
            crate::post_quantum_available(),
            "prefer offers hybrid exactly when this build has ML-KEM, and silently becomes off \
             (no hybrid group in the dialed config) otherwise"
        );
    }

    #[test]
    fn upstream_pq_suppression_window() {
        let state = PqState::new(DEFAULT_PQ_SUPPRESS_SECS);
        assert!(
            state.offer_hybrid(UpstreamPq::Prefer, UnixSeconds::new(0)),
            "fixture precondition: a fresh state offers hybrid immediately"
        );

        state.record_failure(UnixSeconds::new(1_000));
        assert!(
            !state.offer_hybrid(
                UpstreamPq::Prefer,
                UnixSeconds::new(1_000 + u64::from(DEFAULT_PQ_SUPPRESS_SECS) - 1)
            ),
            "one second before the window closes, hybrid must still be suppressed"
        );
        assert!(
            state.offer_hybrid(
                UpstreamPq::Prefer,
                UnixSeconds::new(1_000 + u64::from(DEFAULT_PQ_SUPPRESS_SECS))
            ),
            "exactly at the window boundary, hybrid must be offered again"
        );

        // `off` and `require` ignore suppression entirely.
        assert!(!state.offer_hybrid(UpstreamPq::Off, UnixSeconds::new(1_000)));
        assert!(state.offer_hybrid(UpstreamPq::Require, UnixSeconds::new(1_000)));
    }

    #[test]
    fn upstream_pq_success_clears() {
        let state = PqState::new(DEFAULT_PQ_SUPPRESS_SECS);
        state.record_failure(UnixSeconds::new(1_000));
        assert!(!state.offer_hybrid(UpstreamPq::Prefer, UnixSeconds::new(1_000)));
        state.record_success();
        assert!(
            state.offer_hybrid(UpstreamPq::Prefer, UnixSeconds::new(1_000)),
            "a recorded success must clear the suppression immediately, not wait out the window"
        );
    }

    // -----------------------------------------------------------------------
    // Pool key.
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_pool_key_ignores_timeouts() {
        // `UpstreamTlsConfig` has no timeout, retry, weight or metric-label field at all, so
        // there is nothing to twiddle directly; the property this edge case names is instead
        // that `pool_key_component` is a pure function of the real configuration; two
        // independently compiled `UpstreamTls` values from byte-identical configuration input
        // must agree exactly, proving no non-configuration state (an address, a counter, a
        // timestamp) leaks into the key.
        let fx = ca_fixture();
        let anchors: &[&[u8]] = &[&fx.der];
        let cfg = base_cfg("example.com");
        let a = UpstreamTls::compile(&cfg, Some(anchors), None, fresh_stats()).expect("compiles");
        let b = UpstreamTls::compile(&cfg, Some(anchors), None, fresh_stats()).expect("compiles");
        assert_eq!(a.pool_key_component(), b.pool_key_component());
    }

    /// `(label, config, anchors, client credential)` for one pool-key variant case.
    type PoolKeyVariant<'a> = (
        &'a str,
        UpstreamTlsConfig,
        Option<&'a [&'a [u8]]>,
        Option<Arc<Credentials>>,
    );

    #[test]
    fn upstream_pool_key_covers_security() {
        let fx = ca_fixture();
        let other = other_ca_fixture();
        let anchors: &[&[u8]] = &[&fx.der];
        let other_anchors: &[&[u8]] = &[&other.der];
        let client_cred = client_cred_fixture();

        // The base configuration carries one SAN already (not an empty list), so the "SANs"
        // variant below can change WHICH identity is accepted while leaving the SAN count (and
        // therefore the verify-mode discriminant) unchanged. Without this, an empty-to-one-SAN
        // variant would ALSO flip the Hostname/Identity discriminant, and the pool key would
        // differ for that reason alone, never actually exercising whether the SAN VALUE itself
        // is part of the hash.
        let base_cfg_v = UpstreamTlsConfig {
            subject_alt_names: vec![SubjectAltName::Hostname {
                hostname: "base-san.example.com".to_owned(),
            }],
            ..base_cfg("base.example.com")
        };
        let base = UpstreamTls::compile(&base_cfg_v, Some(anchors), None, fresh_stats())
            .expect("base compiles");
        let base_key = base.pool_key_component();

        let variants: Vec<PoolKeyVariant<'_>> = vec![
            (
                "hostname",
                UpstreamTlsConfig {
                    hostname: "other.example.com".to_owned(),
                    ..base_cfg_v.clone()
                },
                Some(anchors),
                None,
            ),
            (
                "alpn",
                UpstreamTlsConfig {
                    alpn: vec!["h2".to_owned()],
                    ..base_cfg_v.clone()
                },
                Some(anchors),
                None,
            ),
            ("anchors", base_cfg_v.clone(), Some(other_anchors), None),
            (
                "verify mode (insecure)",
                UpstreamTlsConfig {
                    insecure_skip_verify: true,
                    i_accept_the_risk: true,
                    ..base_cfg_v.clone()
                },
                None,
                None,
            ),
            (
                "SANs",
                UpstreamTlsConfig {
                    // A DIFFERENT single SAN, not an added one: the count (and therefore the
                    // verify-mode discriminant) stays identical to the base, isolating the SAN
                    // VALUE as the only thing that changed.
                    subject_alt_names: vec![SubjectAltName::Hostname {
                        hostname: "different-san.example.com".to_owned(),
                    }],
                    ..base_cfg_v.clone()
                },
                Some(anchors),
                None,
            ),
            (
                "client credential",
                base_cfg_v.clone(),
                Some(anchors),
                Some(Arc::clone(&client_cred)),
            ),
            (
                "post-quantum mode",
                UpstreamTlsConfig {
                    post_quantum: UpstreamPq::Prefer,
                    ..base_cfg_v.clone()
                },
                Some(anchors),
                None,
            ),
        ];

        for (label, cfg, anchors_arg, cred) in variants {
            let compiled = UpstreamTls::compile(&cfg, anchors_arg, cred, fresh_stats())
                .unwrap_or_else(|e| panic!("variant {label} must compile: {e}"));
            assert_ne!(
                compiled.pool_key_component(),
                base_key,
                "variant {label} must change the pool key"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Peer input bounds.
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_peer_leaf_too_large() {
        // The exact boundary, pinned directly against the predicate `verify_server_cert` calls:
        // MAX_DER_BYTES itself is accepted (defers to the rest of the checks), one byte more is
        // rejected on size alone. See `peer_leaf_size_ok`'s doc comment for why this cannot also
        // be pinned through a constructed certificate: rustls-webpki independently refuses any
        // certificate over the same 65,536-byte threshold, so there is no real, chain-valid
        // certificate that is over our cap and under webpki's own.
        assert!(
            peer_leaf_size_ok(MAX_DER_BYTES),
            "the boundary itself must be accepted"
        );
        assert!(
            !peer_leaf_size_ok(MAX_DER_BYTES + 1),
            "one byte over the boundary must be rejected"
        );

        // End to end: `verify_server_cert` on an identity-mode verifier rejects an oversized
        // peer leaf through the chain_rejects bucket, before parse_peer_sans (and therefore
        // before identity_mismatch) is ever reached.
        let fx = ca_fixture();
        let (verifier, stats) = identity_verifier(
            fx,
            vec![CompiledSan::Uri(Box::from(
                "spiffe://example.org/ns/prod/sa/backend",
            ))],
        );
        let oversized = vec![0xAAu8; MAX_DER_BYTES + 1];
        assert!(verify(&verifier, &oversized).is_err());
        assert_eq!(stats.chain_rejects.load(Ordering::Relaxed), 1);
        assert_eq!(stats.identity_mismatch.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn upstream_peer_sans_over_cap() {
        let fx = ca_fixture();
        let target = "target.example.com";
        // 1001 dNSName SANs, with the one identity matching the configured SAN placed LAST, so
        // acceptance would require scanning past the cap. Small names keep the whole leaf well
        // under MAX_DER_BYTES, isolating the SAN-count cap from the byte-size cap tested above.
        let mut dns_sans: Vec<String> = (0..1_000).map(|i| format!("h{i}.example.com")).collect();
        dns_sans.push(target.to_owned());
        assert_eq!(dns_sans.len(), MAX_PEER_SANS + 1, "fixture precondition");
        let dns_refs: Vec<&str> = dns_sans.iter().map(String::as_str).collect();

        let (verifier, stats) = identity_verifier(fx, vec![CompiledSan::Dns(Box::from(target))]);
        let leaf = leaf_cert(fx, &dns_refs, &[]);
        assert!(
            leaf.len() <= MAX_DER_BYTES,
            "fixture precondition: this leaf must be rejected for its SAN COUNT, not its byte size"
        );
        let result = verify(&verifier, &leaf);
        assert!(
            result.is_err(),
            "a peer certificate with more than MAX_PEER_SANS relevant entries must be rejected \
             without ever reaching the matching identity"
        );
        assert_eq!(stats.identity_mismatch.load(Ordering::Relaxed), 1);
    }

    // -----------------------------------------------------------------------
    // The unverified-connection warning.
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_unverified_warning_rate_limited() {
        ensure_provider_installed();
        let stats = fresh_stats();
        let cfg = insecure_cfg("example.com");
        let compiled = UpstreamTls::compile(&cfg, None, None, Arc::clone(&stats))
            .expect("insecure config must compile");
        assert!(compiled.logs_unverified_warning());

        let provider = Arc::clone(crate::provider::provider().expect("provider installed"));
        let insecure_verifier = InsecureVerifier {
            provider,
            stats: Arc::clone(&stats),
        };
        let end_entity = CertificateDer::from(vec![0u8; 4]);
        let server_name = any_server_name();

        let mut emitted = 0u32;
        for _ in 0..1_000 {
            insecure_verifier
                .verify_server_cert(&end_entity, &[], &server_name, &[], now())
                .expect("the insecure verifier accepts every chain");
            if compiled.should_emit_unverified_warning(UnixSeconds::new(NOW_SECS)) {
                emitted += 1;
            }
        }
        assert_eq!(
            emitted, 1,
            "1000 connection establishments within the same second must emit exactly one warning line"
        );
        assert_eq!(
            stats.unverified_connections.load(Ordering::Relaxed),
            1_000,
            "the counter carries the true, un-rate-limited volume"
        );

        // A minute boundary inside the burst: a second warning line is allowed, and exactly one
        // more, not a flood.
        assert!(compiled.should_emit_unverified_warning(UnixSeconds::new(
            NOW_SECS + UNVERIFIED_WARNING_WINDOW_SECS
        )));
        assert!(!compiled.should_emit_unverified_warning(UnixSeconds::new(
            NOW_SECS + UNVERIFIED_WARNING_WINDOW_SECS
        )));
    }

    // -----------------------------------------------------------------------
    // Property tests.
    // -----------------------------------------------------------------------

    fn client_cred_fixture() -> Arc<Credentials> {
        static FIXTURE: OnceLock<Arc<Credentials>> = OnceLock::new();
        Arc::clone(FIXTURE.get_or_init(|| {
            ensure_provider_installed();
            let key =
                rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
            let params = rcgen::CertificateParams::new(vec!["client.example".to_owned()])
                .expect("valid SAN");
            let cert = params.self_signed(&key).expect("self sign");
            let mut interner = crate::store::ChainInterner::new();
            Arc::new(
                Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                    .expect("valid leaf and key"),
            )
        }))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Differs one `ConfigWithExtras`-shaped input from a base case along exactly one of
        /// nine dimensions: the seven behaviour-affecting ones (hostname, ALPN, anchors, verify
        /// mode, SANs, client credential, post-quantum mode) plus two dummy ones (a timeout and
        /// a label) that are never passed to `compile` at all. The pool key must differ in the
        /// first seven cases and must not differ in the last two.
        #[test]
        fn prop_pool_key_covers_exactly_the_security_fields(field_idx in 0..9u8) {
            let fx1 = ca_fixture();
            let fx2 = other_ca_fixture();
            let base_anchors: &[&[u8]] = &[&fx1.der];
            let alt_anchors: &[&[u8]] = &[&fx2.der];

            // The base carries one SAN already, not an empty list, so field_idx==4 below can
            // change WHICH identity is accepted without also flipping the SAN count (and
            // therefore the Hostname/Identity verify-mode discriminant), which would otherwise
            // change the key for a reason unrelated to the SAN's own bytes.
            let base = UpstreamTlsConfig {
                subject_alt_names: vec![SubjectAltName::Hostname {
                    hostname: "base-san.example.com".to_owned(),
                }],
                ..base_cfg("base.example.com")
            };
            let mut variant = base.clone();
            let mut variant_anchors_arg: Option<&[&[u8]]> = Some(base_anchors);
            let mut variant_cred: Option<Arc<Credentials>> = None;
            // The two fields this test's generator carries that are NOT part of
            // `UpstreamTlsConfig` at all, representing a timeout and a metric label a real
            // upstream document would also carry alongside its TLS block.
            let base_timeout: u32 = 30;
            let mut variant_timeout: u32 = base_timeout;
            let base_label = "base-label".to_owned();
            let mut variant_label = base_label.clone();
            let expect_change: bool;

            match field_idx {
                0 => { variant.hostname = "other.example.com".to_owned(); expect_change = true; }
                1 => { variant.alpn = vec!["h2".to_owned()]; expect_change = true; }
                2 => { variant_anchors_arg = Some(alt_anchors); expect_change = true; }
                3 => {
                    variant.insecure_skip_verify = true;
                    variant.i_accept_the_risk = true;
                    variant_anchors_arg = None;
                    expect_change = true;
                }
                4 => {
                    // A different SAN, not an added one: same count, different value.
                    variant.subject_alt_names = vec![SubjectAltName::Hostname {
                        hostname: "different-san.example.com".to_owned(),
                    }];
                    expect_change = true;
                }
                5 => { variant_cred = Some(client_cred_fixture()); expect_change = true; }
                6 => { variant.post_quantum = UpstreamPq::Prefer; expect_change = true; }
                7 => { variant_timeout = base_timeout + 1; expect_change = false; }
                _ => { variant_label = format!("{base_label}-x"); expect_change = false; }
            }

            let compiled_a = UpstreamTls::compile(&base, Some(base_anchors), None, fresh_stats())
                .expect("base config must compile");
            let compiled_b = UpstreamTls::compile(&variant, variant_anchors_arg, variant_cred, fresh_stats())
                .expect("variant config must compile");

            let key_a = compiled_a.pool_key_component();
            let key_b = compiled_b.pool_key_component();

            if expect_change {
                prop_assert_ne!(
                    key_a, key_b,
                    "field_idx={} must change the pool key (timeout {}->{}, label {:?}->{:?})",
                    field_idx, base_timeout, variant_timeout, base_label, variant_label
                );
            } else {
                prop_assert_eq!(
                    key_a, key_b,
                    "field_idx={} must NOT change the pool key (timeout {}->{}, label {:?}->{:?})",
                    field_idx, base_timeout, variant_timeout, base_label, variant_label
                );
            }
        }
    }

    /// A `CertIndex` with exactly one wildcard entry, `*.example.com`, built once and shared by
    /// every case of `prop_wildcard_san_matches_like_cert_index`.
    fn wildcard_index_fixture() -> &'static crate::store::CertIndex {
        static FIXTURE: OnceLock<crate::store::CertIndex> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            ensure_provider_installed();
            let key =
                rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
            let params =
                rcgen::CertificateParams::new(vec!["dummy.example".to_owned()]).expect("valid SAN");
            let cert = params.self_signed(&key).expect("self sign");
            let mut interner = crate::store::ChainInterner::new();
            let cred = Arc::new(
                Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                    .expect("valid leaf and key"),
            );
            let mut builder = crate::store::CertIndexBuilder::new([7u8; 16]);
            builder
                .upsert_wildcard("*.example.com", cred)
                .expect("valid wildcard");
            builder.build().expect("index builds")
        })
    }

    proptest! {
        /// `prefix` is 0 to 2 extra labels prepended to either the configured parent
        /// (`example.com`, chosen about half the time) or an unrelated domain, which is what
        /// gives this generator a real chance of landing in BOTH the match and the no-match
        /// branch rather than almost never matching by pure chance.
        #[test]
        fn prop_wildcard_san_matches_like_cert_index(
            prefix in proptest::collection::vec("[a-z0-9]{1,6}", 0..3),
            use_configured_parent in any::<bool>(),
            other_suffix in "[a-z0-9]{1,6}\\.[a-z0-9]{2,4}",
        ) {
            let index = wildcard_index_fixture();
            let suffix = if use_configured_parent { "example.com".to_owned() } else { other_suffix };
            let mut candidate = prefix.join(".");
            if !candidate.is_empty() {
                candidate.push('.');
            }
            candidate.push_str(&suffix);

            let mut buf = [0u8; MAX_NAME_LEN];
            let Ok(normalized) = name::normalize(&candidate, &mut buf) else {
                return Ok(());
            };
            let mine = name::parent(normalized) == Some("example.com");
            let oracle = index.resolve(&candidate, crate::store::ClientCaps::all()).is_some();
            prop_assert_eq!(mine, oracle, "candidate={:?}", candidate);
        }
    }
}
