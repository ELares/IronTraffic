// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client certificate authentication that cannot be configured to fail open.
//!
//! Caddy shipped CVE-2026-27586: mTLS client authentication silently failed open when the CA
//! certificate file was missing or malformed. A typo in a path, a partially written file during a
//! config push, or a truncated secret mount turned an authenticated endpoint into an open one,
//! with no error and no log. The correction here is structural rather than a check someone has to
//! remember to add: [`TrustAnchors`] cannot be constructed empty. Its constructor returns a
//! `Result`, an empty or unparseable bundle is an `Err` at configuration compile time, and a
//! listener whose configuration fails to compile never binds. There is no path from "the CA file
//! was missing" to "accept any client".
//!
//! [`ClientAuth`] models the mode as data: `None` requests no certificate, and `Optional` and
//! `Required` each hold a [`TrustAnchors`] by value, so "required but no anchors" is not a state
//! this type can represent at all. That is the whole correction; see the issue's own "Why this
//! design and not the obvious alternative" for the `Option<Arc<RootCertStore>>` plus a boolean
//! shape this replaces, which is what makes Caddy's CVE representable in the first place.
//!
//! [`IronClientVerifier`] does the verification: chain validation is delegated to
//! `rustls-webpki` unchanged (its defaults, `RevocationCheckDepth::Chain` and
//! `UnknownStatusPolicy::Deny`, are correct and are kept), and revocation is checked afterward
//! against this crate's own compiled [`crate::crl::RevocationIndex`] rather than handed to webpki
//! as a `Vec<CertificateRevocationListDer>`, which is an O(r) scan per verification against an
//! index that can hold millions of serials. **Building the webpki verifier WITHOUT CRLs changes
//! one default, and getting it wrong bricks every mTLS listener**: webpki's own
//! `UnknownStatusPolicy::Deny` only applies to issuers whose CRLs were supplied to IT, so an empty
//! `crls` argument to `WebPkiClientVerifier::builder` would make it perform no revocation checking
//! at all. This module's `RevocationMode::Enforced` (the default) is the explicit statement that
//! every chain element's issuer must have a usable index in *our* `CrlSet`, checked in
//! [`IronClientVerifier::new`] rather than left to be discovered as an opaque handshake alert the
//! first time a client connects; `RevocationMode::Disabled` is the explicit opposite, and there is
//! no third, implicit state where the absence of CRLs quietly means "do not check".
//!
//! No OCSP request, DNS lookup, file read, or any other I/O ever happens inside
//! `verify_client_cert`: one inbound handshake becoming one outbound request is a self-inflicted
//! amplification attack against us and against the CA, and the asynchronous client-certificate
//! OCSP mode this would require is explicitly out of scope for this issue (see the issue's own
//! Context section for the later, unpublished slug that would carry it).
//!
//! Compressed client certificates (RFC 8879) are never advertised: this crate does not enable
//! rustls's `zlib` or `brotli` features and never installs a client-certificate decompressor, so
//! accepting attacker-supplied compressed certificates as a decompression-bomb surface is not
//! representable here either.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use der::Decode;
use der::Reader as _;

use crate::crl::{CrlConfig, CrlSet, Freshness};
use crate::listener::ClientAuthKind;
use crate::store::TimeView;

/// Maximum trust anchors whose subject DNs are sent as root hints in the `CertificateRequest`.
/// Above this the hint list is cleared: it is sent to every unauthenticated peer, so it is both a
/// disclosure of the trust bundle's contents and a bandwidth amplification factor an attacker gets
/// for free. Below the cap the hints are genuinely useful: a client holding several certificates
/// can pick the one this listener will actually accept.
pub const MAX_ROOT_HINTS: usize = 32;

/// A non-empty set of trust anchors. Cannot be constructed empty; that is the point.
///
/// `Clone` is required because [`ClientAuth`] derives it and holds one by value; every field here
/// is an `Arc` or `Copy`, so the clone is a refcount bump, never a re-parse.
#[derive(Clone)]
pub struct TrustAnchors {
    roots: Arc<rustls::RootCertStore>,
    /// BLAKE3 of the sorted anchor DER blobs, truncated to 16 bytes. Used as the pool-key
    /// component and reported by the admin API so an operator can see which bundle is live.
    id: [u8; 16],
    count: usize,
}

impl TrustAnchors {
    /// Build from DER anchors.
    ///
    /// 1. An empty bundle is refused: this is CVE-2026-27586.
    /// 2. Every blob must be non-empty, no larger than [`crate::store::MAX_DER_BYTES`], and must
    ///    parse. The best-effort, skip-what-fails loader `rustls::RootCertStore` also offers is
    ///    never used here: a bundle where 3 of 4 anchors parsed is a broken bundle, not a 75%
    ///    bundle, and naming the failing index lets the operator find it.
    /// 3. The resulting store must be non-empty (defense in depth; unreachable today given step
    ///    2's per-anchor handling, but the issue's own design states it as an independent check
    ///    and a future change to step 2 must not silently reopen the empty-bundle case).
    /// 4. The identity is `blake3` over the anchors sorted lexicographically by DER bytes, so a
    ///    reordered bundle (same anchors, different file order) keeps the same id: the id is a
    ///    pool-key component and a reordered bundle must not invalidate every upstream pool.
    ///
    /// # Errors
    /// [`ClientAuthError::EmptyTrustBundle`], [`ClientAuthError::EmptyAnchor`],
    /// [`ClientAuthError::AnchorTooLarge`], [`ClientAuthError::AnchorParse`].
    pub fn from_der_bundle(anchors: &[&[u8]]) -> Result<Self, ClientAuthError> {
        if anchors.is_empty() {
            return Err(ClientAuthError::EmptyTrustBundle);
        }

        let mut store = rustls::RootCertStore::empty();
        for (index, blob) in anchors.iter().enumerate() {
            if blob.is_empty() {
                return Err(ClientAuthError::EmptyAnchor);
            }
            if blob.len() > crate::store::MAX_DER_BYTES {
                return Err(ClientAuthError::AnchorTooLarge);
            }
            store
                .add(rustls::pki_types::CertificateDer::from((*blob).to_vec()))
                .map_err(|_| ClientAuthError::AnchorParse { index })?;
        }
        if store.is_empty() {
            return Err(ClientAuthError::EmptyTrustBundle);
        }

        let mut sorted: Vec<&[u8]> = anchors.to_vec();
        sorted.sort_unstable();
        let mut hasher = blake3::Hasher::new();
        for blob in &sorted {
            hasher.update(blob);
        }
        let digest = hasher.finalize();
        let mut id = [0u8; 16];
        if let Some(head) = digest.as_bytes().get(..16) {
            id.copy_from_slice(head);
        }

        Ok(Self {
            roots: Arc::new(store),
            id,
            count: anchors.len(),
        })
    }

    /// Number of anchors. Always at least 1.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether this bundle has no anchors. Always `false`: [`Self::from_der_bundle`] cannot
    /// produce an empty bundle. Provided because clippy's `len_without_is_empty` otherwise fires
    /// on every caller of [`Self::len`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Stable identity of this bundle: BLAKE3 of the sorted anchor DER, truncated to 16 bytes.
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// Lowercase hex of [`Self::id`], for logs and the admin API.
    #[must_use]
    pub fn id_hex(&self) -> [u8; 32] {
        hex32(self.id)
    }

    /// The anchors as rustls-webpki trust anchors, for the one caller that must do name-free path
    /// verification: `UpstreamVerifier` in issue `upstream-tls-verification-and-identity` (#125).
    ///
    /// `pub(crate)` on purpose: it exposes a `rustls_pki_types` type and must not cross the crate
    /// facade. rustls 0.23's `RootCertStore` has one public field, `roots: Vec<TrustAnchor<'static>>`.
    #[allow(
        dead_code,
        reason = "no caller exists yet in this tree: the one caller this method is for, \
                  UpstreamVerifier, is upstream-tls-verification-and-identity (#125), which has \
                  not landed. Removing the method until then would mean re-adding the identical \
                  pub(crate) crossing later instead of the one-line reason this comment already \
                  is; the method's shape (a borrow into TrustAnchors's own store, no allocation) \
                  is exactly what #125 needs and is worth pinning now."
    )]
    pub(crate) fn webpki_anchors(&self) -> &[rustls::pki_types::TrustAnchor<'static>] {
        &self.roots.roots
    }
}

/// Lowercase hex encoding of a 16-byte value, 32 ASCII characters, no separators.
///
/// Duplicated rather than shared: `store::cred::CertFingerprint::to_hex` has the identical body
/// but no public constructor from arbitrary bytes, and `crate::ticket`'s `hex16` encodes 8 bytes
/// into 16 characters, the wrong width for this type's 16-byte id. A fourth private hex encoder in
/// this crate is the established shape here, not a shortcut around one.
fn hex32(bytes: [u8; 16]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 32];
    for (i, byte) in bytes.iter().enumerate() {
        if let Some(hi) = out.get_mut(i * 2) {
            *hi = *HEX.get(usize::from(byte >> 4)).unwrap_or(&b'0');
        }
        if let Some(lo) = out.get_mut(i * 2 + 1) {
            *lo = *HEX.get(usize::from(byte & 0x0f)).unwrap_or(&b'0');
        }
    }
    out
}

/// How a listener authenticates clients.
#[derive(Clone)]
pub enum ClientAuth {
    /// No client certificate is requested.
    None,
    /// A certificate is requested and verified if presented; a client with none is admitted.
    Optional(TrustAnchors),
    /// A certificate is required and verified.
    Required(TrustAnchors),
}

impl ClientAuth {
    /// Compile a configuration plus an optional bundle into a mode.
    ///
    /// `mode: none` ignores `anchors` entirely (a bundle supplied alongside `none` signals a
    /// configuration mistake, but the mode still wins: "none" never means "sometimes optional").
    /// `mode: optional` and `mode: required` both require a non-empty, parseable bundle; the
    /// distinction between "no bundle was supplied at all" ([`ClientAuthError::ModeWithoutAnchors`])
    /// and "a bundle was supplied but it was empty or broken"
    /// ([`ClientAuthError::EmptyTrustBundle`] and friends) is deliberate, because they are
    /// different operator mistakes: a missing resource reference versus a resource that resolved
    /// to garbage.
    ///
    /// # Errors
    /// [`ClientAuthError::ModeWithoutAnchors`] when the mode needs anchors and none were supplied,
    /// plus anything [`TrustAnchors::from_der_bundle`] returns.
    pub fn compile(
        cfg: &ClientAuthConfig,
        anchors: Option<&[&[u8]]>,
    ) -> Result<Self, ClientAuthError> {
        match cfg.mode {
            ClientAuthMode::None => Ok(ClientAuth::None),
            ClientAuthMode::Optional => {
                let anchors = anchors.ok_or(ClientAuthError::ModeWithoutAnchors)?;
                Ok(ClientAuth::Optional(TrustAnchors::from_der_bundle(
                    anchors,
                )?))
            }
            ClientAuthMode::Required => {
                let anchors = anchors.ok_or(ClientAuthError::ModeWithoutAnchors)?;
                Ok(ClientAuth::Required(TrustAnchors::from_der_bundle(
                    anchors,
                )?))
            }
        }
    }

    /// The kind, for the listener divergence lint in `sni-server-config-selection` (#119).
    #[must_use]
    pub fn kind(&self) -> ClientAuthKind {
        match self {
            ClientAuth::None => ClientAuthKind::None,
            ClientAuth::Optional(_) => ClientAuthKind::Optional,
            ClientAuth::Required(_) => ClientAuthKind::Required,
        }
    }

    /// The trust anchors, if this mode has any.
    #[must_use]
    pub fn anchors(&self) -> Option<&TrustAnchors> {
        match self {
            ClientAuth::None => None,
            ClientAuth::Optional(a) | ClientAuth::Required(a) => Some(a),
        }
    }
}

/// `mode`, as configured. `none`, `optional`, or `required`.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ClientAuthMode {
    /// No client certificate requested. The default.
    #[default]
    None,
    /// Requested and verified if presented.
    Optional,
    /// Required.
    Required,
}

/// Whether the client-certificate path checks revocation.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum RevocationMode {
    /// Every chain element's issuer must have a usable revocation index. The default.
    #[default]
    Enforced,
    /// No revocation check runs. An explicit operator statement, warned about at every compile.
    Disabled,
}

/// Operator-facing configuration.
///
/// The CA bundle itself is deliberately absent from this type: bundles are referenced by
/// resource, and the configuration milestone resolves the reference to bytes before calling
/// [`TrustAnchors::from_der_bundle`]. That keeps secret-bearing bytes out of the config document
/// type, which the workspace's secret-handling rule requires.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ClientAuthConfig {
    /// `none`, `optional`, or `required`. Default `none`.
    #[serde(default)]
    pub mode: ClientAuthMode,
    /// Accept a certificate whose revocation status could not be determined. Default false.
    /// Setting this to true is what an operator does deliberately to weaken the check; it is
    /// exported as `tls_client_auth_unknown_revocation_allowed` for whatever component wires this
    /// crate's data to a metrics exporter, in the same "expose the value, do not embed the
    /// exporter" shape `TlsPolicy::startup_warnings` already uses in this crate for its own
    /// configuration-mistake warnings.
    #[serde(default)]
    pub allow_unknown_revocation_status: bool,
    /// Whether revocation is checked at all. Default `enforced`. This is an explicit field rather
    /// than "check if CRLs happen to be present", because that would mean an operator who forgets
    /// to configure CRLs gets NO revocation checking with no signal, the same silent failure this
    /// whole module exists to remove.
    #[serde(default)]
    pub revocation: RevocationMode,
}

/// Why client authentication failed to configure.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ClientAuthError {
    /// The trust bundle contained no anchors. This is the fail-open CVE, refused.
    EmptyTrustBundle,
    /// One anchor was zero bytes.
    EmptyAnchor,
    /// One anchor exceeded the DER size cap.
    AnchorTooLarge,
    /// One anchor did not parse. Carries its index in the bundle.
    AnchorParse {
        /// Zero-based index within the bundle.
        index: usize,
    },
    /// rustls-webpki refused to build a verifier.
    VerifierBuild,
    /// `mode` is `optional` or `required` but no trust bundle was supplied.
    ModeWithoutAnchors,
    /// `revocation` is `enforced` but the `CrlSet` holds no index at all, so every client
    /// certificate would be rejected. Refused at compile time rather than at connection time.
    RevocationEnforcedWithoutCrls,
}

impl core::fmt::Display for ClientAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientAuthError::EmptyTrustBundle => f.write_str(
                "the client authentication trust bundle is empty; refusing to configure client \
                 authentication that would admit every peer (CVE-2026-27586)",
            ),
            ClientAuthError::EmptyAnchor => {
                f.write_str("a trust anchor in the bundle was zero bytes")
            }
            ClientAuthError::AnchorTooLarge => {
                f.write_str("a trust anchor in the bundle exceeded 65536 bytes")
            }
            ClientAuthError::AnchorParse { index } => {
                write!(f, "trust anchor at index {index} did not parse as X.509 DER")
            }
            ClientAuthError::VerifierBuild => {
                f.write_str("rustls-webpki refused to build a client certificate verifier")
            }
            ClientAuthError::ModeWithoutAnchors => f.write_str(
                "client authentication mode is optional or required but no trust bundle was supplied",
            ),
            ClientAuthError::RevocationEnforcedWithoutCrls => f.write_str(
                "revocation is enforced but no CRL is configured, so every client certificate \
                 would be rejected; supply a CRL for each issuing CA, or set revocation: disabled \
                 deliberately",
            ),
        }
    }
}

impl std::error::Error for ClientAuthError {}

/// Counters for the client authentication path. No field here is ever labelled with a
/// peer-supplied value (subject, serial, or issuer): a client chooses those values, and a labelled
/// counter over them is an unbounded-cardinality memory attack any peer can drive.
#[derive(Debug, Default)]
pub struct ClientAuthStats {
    /// `tls_client_auth_accepted_total`
    pub accepted: AtomicU64,
    /// `tls_client_auth_chain_reject_total`
    pub chain_rejects: AtomicU64,
    /// `tls_client_auth_revoked_total`
    pub revoked_denied: AtomicU64,
    /// `tls_client_auth_unknown_revocation_denied_total`
    pub unknown_denied: AtomicU64,
    /// `tls_client_auth_unknown_revocation_allowed_total`
    pub unknown_allowed: AtomicU64,
    /// `tls_client_auth_stale_crl_used_total`
    pub stale_crl_used: AtomicU64,
    /// `tls_client_auth_expired_crl_denied_total`
    pub expired_crl_denied: AtomicU64,
    /// `tls_client_auth_malformed_chain_cert_total`
    pub malformed_chain_cert: AtomicU64,
}

/// Verifies client certificates: chain validation by rustls-webpki, revocation by our index.
pub struct IronClientVerifier {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    crls: Arc<CrlSet>,
    /// [`TrustAnchors::id`] of the bundle this verifier was built from. Not read by
    /// `verify_client_cert` (the inner verifier already carries the actual roots); kept so this
    /// type's `Debug` output can show an operator which bundle is live, the same thing the admin
    /// API shows for [`TrustAnchors::id_hex`], without printing anything secret.
    anchors_id: [u8; 16],
    allow_unknown_revocation: bool,
    /// Whether the revocation loop in `verify_client_cert` runs at all. Step 2 reads this, so it
    /// must be a field: the `revocation` argument to `new` is stored here and nowhere else.
    revocation: RevocationMode,
    crl_cfg: CrlConfig,
    time: Arc<dyn TimeView>,
    stats: ClientAuthStats,
}

impl core::fmt::Debug for IronClientVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `inner` is deliberately not rendered: rustls's own verifier Debug impl can reach key
        // material through the root store, and a Debug line is exactly how that reaches a log.
        f.debug_struct("IronClientVerifier")
            .field("anchors_id", &hex_str(self.anchors_id))
            .field("revocation", &self.revocation)
            .field("allow_unknown_revocation", &self.allow_unknown_revocation)
            .finish_non_exhaustive()
    }
}

/// Renders a 16-byte id as a `&str` for `Debug` output, falling back to a fixed placeholder in
/// the (unreachable, since [`hex32`] only ever emits ASCII hex digits) case the bytes are not
/// valid UTF-8, so a `Debug` impl can never panic on the data it prints.
fn hex_str(id: [u8; 16]) -> String {
    let hex = hex32(id);
    core::str::from_utf8(&hex)
        .unwrap_or("<invalid>") // it-allow: no-panic reason: hex32 only ever writes ASCII hex digit bytes, so this branch cannot be reached by any input; kept as a non-panicking fallback rather than an unwrap so Debug can never panic regardless.
        .to_owned() // it-allow: hot-path-allocation reason: Debug formatting is diagnostic output, not the request path, and runs at most once per formatted log line.
}

impl IronClientVerifier {
    /// Build a verifier.
    ///
    /// Returns `Ok(None)` for [`ClientAuth::None`], because a listener with no client
    /// authentication installs no verifier at all rather than installing a permissive one.
    ///
    /// # Errors
    /// [`ClientAuthError::VerifierBuild`], or [`ClientAuthError::RevocationEnforcedWithoutCrls`]
    /// when `revocation` is [`RevocationMode::Enforced`] and `crls.is_empty()`.
    pub fn new(
        auth: &ClientAuth,
        crls: Arc<CrlSet>,
        crl_cfg: CrlConfig,
        allow_unknown_revocation: bool,
        revocation: RevocationMode,
        time: Arc<dyn TimeView>,
    ) -> Result<Option<Self>, ClientAuthError> {
        let anchors = match auth {
            ClientAuth::None => return Ok(None),
            ClientAuth::Optional(a) | ClientAuth::Required(a) => a,
        };

        if revocation == RevocationMode::Enforced && crls.is_empty() {
            return Err(ClientAuthError::RevocationEnforcedWithoutCrls);
        }

        let provider = crate::provider::provider().ok_or(ClientAuthError::VerifierBuild)?;
        let mut builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::clone(&anchors.roots),
            Arc::clone(provider),
        );
        if matches!(auth, ClientAuth::Optional(_)) {
            builder = builder.allow_unauthenticated();
        }
        // Root hint subjects are the DNs of every trust anchor, sent in the `CertificateRequest`
        // to every client that reaches this listener, before any authentication. Above the cap
        // that is both a disclosure of the whole trust bundle and a bandwidth amplification
        // factor an attacker gets for free, so the hints are cleared rather than sent. There is no
        // logging dependency in this crate (this issue adds none; see its Files table note), so
        // the "log once at info naming the anchor count" the design calls for is not emitted here;
        // whatever wires this crate's data to structured logging later is the place that does,
        // exactly as `TlsPolicy::startup_warnings` already exposes data with no consumer yet in
        // this same crate.
        if anchors.len() > MAX_ROOT_HINTS {
            builder = builder.clear_root_hint_subjects();
        }

        let inner = builder
            .build()
            .map_err(|_| ClientAuthError::VerifierBuild)?;

        Ok(Some(Self {
            inner,
            crls,
            anchors_id: anchors.id(),
            allow_unknown_revocation,
            revocation,
            crl_cfg,
            time,
            stats: ClientAuthStats::default(),
        }))
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &ClientAuthStats {
        &self.stats
    }
}

impl rustls::server::danger::ClientCertVerifier for IronClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // 1. rustls-webpki's alert mapping is already correct; rewriting it would leak which
        // stage failed, so a chain rejection is returned unchanged.
        let verified = match self
            .inner
            .verify_client_cert(end_entity, intermediates, now)
        {
            Ok(v) => v,
            Err(e) => {
                self.stats.chain_rejects.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };

        // 2. Revocation, over the whole chain (end entity then every intermediate), matching
        // `RevocationCheckDepth::Chain`. Skipped entirely when the operator wrote
        // `revocation: disabled`.
        if self.revocation != RevocationMode::Disabled {
            let chain = core::iter::once(end_entity).chain(intermediates.iter());
            for cert in chain {
                let Some((serial, issuer)) = cert_serial_and_issuer(cert.as_ref()) else {
                    self.stats
                        .malformed_chain_cert
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::BadEncoding,
                    ));
                };

                let Some(idx) = self.crls.for_issuer(issuer) else {
                    if self.allow_unknown_revocation {
                        self.stats.unknown_allowed.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.stats.unknown_denied.fetch_add(1, Ordering::Relaxed);
                        return Err(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::UnknownRevocationStatus,
                        ));
                    }
                    continue;
                };

                match idx.freshness(self.time.unix_seconds(), &self.crl_cfg) {
                    Freshness::Fresh => {}
                    Freshness::Stale => {
                        self.stats.stale_crl_used.fetch_add(1, Ordering::Relaxed);
                    }
                    Freshness::Expired => {
                        if self.allow_unknown_revocation {
                            self.stats.unknown_allowed.fetch_add(1, Ordering::Relaxed);
                        } else {
                            self.stats
                                .expired_crl_denied
                                .fetch_add(1, Ordering::Relaxed);
                            return Err(rustls::Error::InvalidCertificate(
                                rustls::CertificateError::UnknownRevocationStatus,
                            ));
                        }
                    }
                }

                if idx.is_revoked(serial) {
                    self.stats.revoked_denied.fetch_add(1, Ordering::Relaxed);
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::Revoked,
                    ));
                }
            }
        }

        // 3.
        self.stats.accepted.fetch_add(1, Ordering::Relaxed);
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Strip a `SEQUENCE` tag and length, returning its content bytes.
///
/// Mirrors `crl.rs`'s private `read_sequence_content` and `ocsp.rs`'s private `sequence_content`,
/// duplicated for the same reason [`normalize_serial`] below is: both modules are outside this
/// issue's Files table, so neither can be widened to export a shared helper.
fn sequence_content(bytes: &[u8]) -> Option<&[u8]> {
    let mut reader = der::SliceReader::new(bytes).ok()?;
    let header = der::Header::decode(&mut reader).ok()?;
    header.tag.assert_eq(der::Tag::Sequence).ok()?;
    reader.read_slice(header.length).ok()
}

/// Strip leading zero octets and treat an all-zero serial as the single byte `0x00`.
///
/// Duplicated from `crl.rs`'s private `normalize_serial` rather than shared: that function is
/// private to the `crl` module, which this issue's Files table does not authorize touching. The
/// two copies MUST stay identical; if the CRL side strips a serial's leading zero and this side
/// does not (or the reverse), revocation silently stops matching. `prop_serial_normalization_agrees_with_crl`
/// below and `crl.rs`'s own `prop_serial_normalization_is_stable` (`crl-revocation-index`, #123)
/// both exist because that failure is silent.
fn normalize_serial(mut bytes: &[u8]) -> &[u8] {
    while let Some((0x00, rest)) = bytes.split_first() {
        if rest.is_empty() {
            break;
        }
        bytes = rest;
    }
    if bytes.is_empty() {
        bytes = &[0x00];
    }
    bytes
}

/// Extract `(serial content octets, issuer Name DER)` from a certificate, borrowing the input.
///
/// Allocation-free. Returns `None` for any input that does not decode as far as the issuer field,
/// which the caller turns into `CertificateError::BadEncoding` rather than a panic: the inner
/// verifier will usually have already rejected genuinely malformed input, so this exists to make
/// sure the revocation loop can never be reached with something it cannot parse, not to be the
/// primary decoder for attacker-controlled bytes.
///
/// Walks the DER exactly as `crl.rs` walks a certificate's issuer field when matching a CRL
/// against it: `Certificate SEQUENCE`, then `TBSCertificate SEQUENCE`, then an optional
/// context-specific `[0]` (the version, discarded), then the `serialNumber INTEGER` (captured and
/// normalized), then the signature `AlgorithmIdentifier SEQUENCE` (skipped), then the `issuer Name`
/// (captured as its full encoded span, tag and length included, because that is what a CRL's
/// issuer field is compared against byte for byte in [`CrlSet::for_issuer`]).
fn cert_serial_and_issuer(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let cert_content = sequence_content(der)?;
    let mut reader = der::SliceReader::new(cert_content).ok()?;
    let tbs_tlv = reader.tlv_bytes().ok()?;

    let tbs_content = sequence_content(tbs_tlv)?;
    let mut tbs = der::SliceReader::new(tbs_content).ok()?;

    if tbs.peek_tag().ok()?.is_context_specific() {
        // The optional `[0] EXPLICIT` version. Discarded, not decoded: this function does not
        // need to know the version number.
        tbs.tlv_bytes().ok()?;
    }

    let serial: der::asn1::UintRef<'_> = tbs.decode().ok()?;
    let serial = normalize_serial(serial.as_bytes());

    // The signature `AlgorithmIdentifier`. Skipped without being decoded: nothing here needs it.
    tbs.tlv_bytes().ok()?;

    // The issuer `Name`, full encoded span.
    let issuer = tbs.tlv_bytes().ok()?;

    Some((serial, issuer))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test module: fixtures are constructed in the test itself, so an unwrap that fires \
              is a broken fixture and must be loud rather than silently reshaping the assertion"
)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Once, OnceLock};
    use std::time::Duration;

    use proptest::prelude::*;
    use rustls::pki_types::UnixTime;
    use rustls::server::danger::ClientCertVerifier as _;

    use super::*;
    use crate::crl::{self, CrlConfig, CrlSet, RevocationIndex};
    use crate::store::TimeView;
    use crate::ticket::{ClusterTicketer, RandNonceSource, TicketRoot};
    use crate::time::UnixSeconds;

    fn ensure_provider_installed() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test module's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
        });
    }

    struct FixedClock(UnixSeconds);
    impl TimeView for FixedClock {
        fn unix_seconds(&self) -> UnixSeconds {
            self.0
        }
    }

    const NOW_SECS: u64 = 1_700_000_000;

    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(NOW_SECS))
    }

    fn clock() -> Arc<dyn TimeView> {
        Arc::new(FixedClock(UnixSeconds::new(NOW_SECS)))
    }

    fn clock_at(secs: u64) -> Arc<dyn TimeView> {
        Arc::new(FixedClock(UnixSeconds::new(secs)))
    }

    fn default_cfg(mode: ClientAuthMode) -> ClientAuthConfig {
        ClientAuthConfig {
            mode,
            allow_unknown_revocation_status: false,
            revocation: RevocationMode::Enforced,
        }
    }

    fn default_crl_cfg() -> CrlConfig {
        CrlConfig::default()
    }

    fn empty_crls() -> Arc<CrlSet> {
        Arc::new(CrlSet::empty())
    }

    /// Unix seconds at midnight UTC on the given calendar date. Only used to place `this_update`
    /// and `next_update` at known, far-apart points; the fine-grained "now" each test actually
    /// varies is a plain `u64` offset from the returned value, never routed back through rcgen.
    fn date_secs(year: i32, month: u8, day: u8) -> u64 {
        let dt = rcgen::date_time_ymd(year, month, day);
        u64::try_from(dt.unix_timestamp()).unwrap_or(0)
    }

    /// One self-signed CA, generated once and shared by every test in this module that needs "a"
    /// CA rather than a specific distinct one: keygen is the slow part, not the per-call sign.
    struct CaFixture {
        key: rcgen::KeyPair,
        params: rcgen::CertificateParams,
        der: Vec<u8>,
    }

    /// `rcgen::CertificateParams::new` does NOT derive the certificate's `subject` from the SAN
    /// list passed to it: everything but `subject_alt_names` comes from `Default::default()`,
    /// which hard-codes `distinguished_name` to the single fixed value `CN=rcgen self signed
    /// cert`. Without this override, every CA this test module builds would share that identical
    /// subject DN regardless of `cn`, which silently broke `client_auth_no_crl_denies` and
    /// `client_auth_no_crl_allowed`: a `CrlSet` built over `other_ca_fixture()` matched
    /// `ca_fixture()`'s issuer anyway, because both had the same subject bytes. Caught by running
    /// those two tests and observing `for_issuer` succeed when the test asserted it must miss.
    fn distinguished_name(cn: &str) -> rcgen::DistinguishedName {
        let mut name = rcgen::DistinguishedName::new();
        name.push(rcgen::DnType::CommonName, cn);
        name
    }

    fn new_ca(cn: &str) -> CaFixture {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keypair generation");
        let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
        params.distinguished_name = distinguished_name(cn);
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
        FIXTURE.get_or_init(|| new_ca("Test Client CA"))
    }

    /// A second, distinct CA (different subject and key), for tests that need two bundles that
    /// must not accept each other's clients or each other's tickets.
    fn other_ca_fixture() -> &'static CaFixture {
        static FIXTURE: OnceLock<CaFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| new_ca("Other Test Client CA"))
    }

    /// A leaf certificate issued by `fx`, for `cn`, carrying `serial` as its `serialNumber`.
    fn client_leaf_with_serial(fx: &CaFixture, cn: &str, serial: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keypair generation");
        let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
        params.distinguished_name = distinguished_name(cn);
        params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
        let issuer = rcgen::Issuer::from_params(&fx.params, &fx.key);
        let cert = params.signed_by(&key, &issuer).expect("sign by CA");
        (cert.der().to_vec(), key.serialize_der())
    }

    /// A leaf certificate issued by `fx`, for `cn`, with an rcgen-assigned serial.
    fn client_leaf(fx: &CaFixture, cn: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keypair generation");
        let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
        params.distinguished_name = distinguished_name(cn);
        let issuer = rcgen::Issuer::from_params(&fx.params, &fx.key);
        let cert = params.signed_by(&key, &issuer).expect("sign by CA");
        (cert.der().to_vec(), key.serialize_der())
    }

    /// An intermediate CA issued by `parent`, itself able to sign further certificates, carrying
    /// `serial` as its own `serialNumber`.
    fn intermediate_ca_with_serial(parent: &CaFixture, cn: &str, serial: &[u8]) -> CaFixture {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keypair generation");
        let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
        params.distinguished_name = distinguished_name(cn);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
        let issuer = rcgen::Issuer::from_params(&parent.params, &parent.key);
        let cert = params.signed_by(&key, &issuer).expect("sign by parent CA");
        let der = cert.der().to_vec();
        CaFixture { key, params, der }
    }

    /// An intermediate CA issued by `parent`, with an rcgen-assigned serial.
    fn intermediate_ca(parent: &CaFixture, cn: &str) -> CaFixture {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keypair generation");
        let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
        params.distinguished_name = distinguished_name(cn);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::Issuer::from_params(&parent.params, &parent.key);
        let cert = params.signed_by(&key, &issuer).expect("sign by parent CA");
        let der = cert.der().to_vec();
        CaFixture { key, params, der }
    }

    fn anchors_for(fx: &CaFixture) -> TrustAnchors {
        TrustAnchors::from_der_bundle(&[&fx.der]).expect("a single real CA must build")
    }

    /// A validly signed CRL over `fx`, revoking `serials`, with a wide (2020..2030) validity
    /// window so tests that do not care about freshness never trip over it by accident.
    fn crl_set_covering(fx: &CaFixture, serials: &[&[u8]]) -> Arc<CrlSet> {
        crl_set_covering_with_updates(fx, serials, date_secs(2020, 1, 1), date_secs(2030, 1, 1))
    }

    fn crl_set_covering_with_updates(
        fx: &CaFixture,
        serials: &[&[u8]],
        this_update_secs: u64,
        next_update_secs: u64,
    ) -> Arc<CrlSet> {
        let idx = revocation_index_for(fx, serials, this_update_secs, next_update_secs);
        Arc::new(CrlSet::from_indices(vec![idx], 1))
    }

    /// A `CrlSet` covering MULTIPLE issuers at once, one wide (2020..2030) index per `(fx,
    /// serials)` pair. Needed whenever a chain crosses more than one issuer: `RevocationCheckDepth::Chain`
    /// means every chain element's OWN issuer is looked up, so a two-level chain (leaf issued by
    /// an intermediate, intermediate issued by a root) needs coverage for both issuers, or the
    /// leaf's own lookup misses before the loop ever reaches the intermediate.
    fn crl_set_covering_multi(pairs: &[(&CaFixture, &[&[u8]])]) -> Arc<CrlSet> {
        let indices = pairs
            .iter()
            .map(|(fx, serials)| {
                revocation_index_for(fx, serials, date_secs(2020, 1, 1), date_secs(2030, 1, 1))
            })
            .collect();
        Arc::new(CrlSet::from_indices(indices, 1))
    }

    fn revocation_index_for(
        fx: &CaFixture,
        serials: &[&[u8]],
        this_update_secs: u64,
        next_update_secs: u64,
    ) -> Arc<RevocationIndex> {
        use rcgen::{
            CertificateRevocationListParams, Issuer, KeyIdMethod, RevokedCertParams, SerialNumber,
        };
        let revocation_time = rcgen::date_time_ymd(2020, 1, 1);
        let revoked_certs = serials
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: SerialNumber::from_slice(s),
                revocation_time,
                reason_code: None,
                invalidity_date: None,
            })
            .collect();
        let issuer = Issuer::from_params(&fx.params, &fx.key);
        let params = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1)
                + (Duration::from_secs(this_update_secs - date_secs(2020, 1, 1))),
            next_update: rcgen::date_time_ymd(2020, 1, 1)
                + (Duration::from_secs(next_update_secs - date_secs(2020, 1, 1))),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let der = params
            .signed_by(&issuer)
            .expect("signing a fixture CRL must not fail")
            .der()
            .to_vec();

        let cfg = default_crl_cfg();
        let parsed = crl::parse(&der, &cfg).expect("fixture CRL must parse");
        let verified = crl::verify_signature(parsed, &fx.der)
            .expect("fixture CRL must verify against its own CA");
        Arc::new(
            RevocationIndex::build(&verified, UnixSeconds::new(this_update_secs), &cfg)
                .expect("fixture CRL must build at its own this_update"),
        )
    }

    fn end_entity(der: &[u8]) -> rustls::pki_types::CertificateDer<'_> {
        rustls::pki_types::CertificateDer::from(der)
    }

    fn chain<'a>(ders: &[&'a [u8]]) -> Vec<rustls::pki_types::CertificateDer<'a>> {
        ders.iter()
            .map(|d| rustls::pki_types::CertificateDer::from(*d))
            .collect()
    }

    /// Extracts the `Err` side of a `Result` whose `Ok` type is not `Debug` (`TrustAnchors` and
    /// `ClientAuth` both derive only `Clone`, per this issue's own Public API, so
    /// `Result::expect_err`/`unwrap_err`, which bound the `Ok` type on `Debug`, cannot be used on
    /// them). Panics with `msg` if `result` was `Ok`.
    fn expect_err_only<T, E>(result: Result<T, E>, msg: &str) -> E {
        match result {
            Ok(_) => panic!("{msg}"),
            Err(e) => e,
        }
    }

    // -----------------------------------------------------------------------
    // TrustAnchors / ClientAuth::compile
    // -----------------------------------------------------------------------

    #[test]
    fn client_auth_empty_bundle_required() {
        let cfg = default_cfg(ClientAuthMode::Required);
        let err = expect_err_only(
            ClientAuth::compile(&cfg, Some(&[])),
            "an empty bundle must refuse",
        );
        assert_eq!(err, ClientAuthError::EmptyTrustBundle);
    }

    #[test]
    fn client_auth_empty_bundle_optional() {
        let cfg = default_cfg(ClientAuthMode::Optional);
        let err = expect_err_only(
            ClientAuth::compile(&cfg, Some(&[])),
            "an empty bundle must refuse",
        );
        assert_eq!(err, ClientAuthError::EmptyTrustBundle);
    }

    #[test]
    fn client_auth_none_with_bundle_warns() {
        let fx = ca_fixture();
        let cfg = default_cfg(ClientAuthMode::None);
        let auth = ClientAuth::compile(&cfg, Some(&[&fx.der]))
            .expect("mode none must ignore any supplied bundle rather than error");
        assert!(
            matches!(auth, ClientAuth::None),
            "a bundle supplied alongside mode:none must be ignored, not silently promoted"
        );
        assert_eq!(auth.kind(), ClientAuthKind::None);
    }

    #[test]
    fn client_auth_required_without_anchors() {
        let cfg = default_cfg(ClientAuthMode::Required);
        assert_eq!(
            expect_err_only(ClientAuth::compile(&cfg, None), "must refuse"),
            ClientAuthError::ModeWithoutAnchors
        );
    }

    #[test]
    fn client_auth_partial_bundle_rejected() {
        let fx = ca_fixture();
        let garbage: &[u8] = b"not a certificate";
        let err = expect_err_only(
            TrustAnchors::from_der_bundle(&[&fx.der, &fx.der, garbage, &fx.der]),
            "a bundle with one unparseable entry must be refused entirely",
        );
        assert_eq!(
            err,
            ClientAuthError::AnchorParse { index: 2 },
            "not a 3-anchor verifier: the whole bundle is refused, naming the failing index"
        );
    }

    #[test]
    fn client_auth_zero_byte_anchor() {
        let empty: &[u8] = &[];
        assert_eq!(
            expect_err_only(TrustAnchors::from_der_bundle(&[empty]), "must refuse"),
            ClientAuthError::EmptyAnchor
        );
    }

    #[test]
    fn client_auth_oversize_anchor() {
        let big = vec![0u8; crate::store::MAX_DER_BYTES + 1];
        assert_eq!(
            expect_err_only(
                TrustAnchors::from_der_bundle(&[big.as_slice()]),
                "must refuse"
            ),
            ClientAuthError::AnchorTooLarge
        );
    }

    #[test]
    fn client_auth_id_is_order_independent() {
        let fx = ca_fixture();
        let other = other_ca_fixture();
        let a = TrustAnchors::from_der_bundle(&[&fx.der, &other.der]).expect("two real CAs");
        let b = TrustAnchors::from_der_bundle(&[&other.der, &fx.der]).expect("two real CAs");
        assert_eq!(a.len(), 2);
        assert_eq!(
            a.id(),
            b.id(),
            "reordering the bundle must not change its id: the id is a pool-key component"
        );
    }

    #[test]
    fn client_auth_kind_matches_mode() {
        let anchors = anchors_for(ca_fixture());
        assert_eq!(ClientAuth::None.kind(), ClientAuthKind::None);
        assert_eq!(
            ClientAuth::Optional(anchors.clone()).kind(),
            ClientAuthKind::Optional
        );
        assert_eq!(
            ClientAuth::Required(anchors).kind(),
            ClientAuthKind::Required
        );
    }

    // -----------------------------------------------------------------------
    // IronClientVerifier::new
    // -----------------------------------------------------------------------

    #[test]
    fn verifier_is_none_for_mode_none() {
        let result = IronClientVerifier::new(
            &ClientAuth::None,
            empty_crls(),
            default_crl_cfg(),
            false,
            RevocationMode::Enforced,
            clock(),
        );
        assert!(
            matches!(result, Ok(None)),
            "a listener with no client authentication must install no verifier at all"
        );
    }

    #[test]
    fn client_auth_enforced_without_crls_refuses() {
        let auth = ClientAuth::Required(anchors_for(ca_fixture()));
        let err = IronClientVerifier::new(
            &auth,
            empty_crls(),
            default_crl_cfg(),
            false,
            RevocationMode::Enforced,
            clock(),
        )
        .expect_err("enforced revocation with no CRL at all must refuse to compile");
        assert_eq!(err, ClientAuthError::RevocationEnforcedWithoutCrls);
    }

    #[test]
    fn client_auth_root_hints_cleared_above_cap() {
        ensure_provider_installed();

        // 32 anchors: at the cap, hints must still be present. One of them is the CA that will
        // actually issue the connecting client's certificate, so the handshake can complete.
        let issuing = new_ca("Root Hint Issuing CA");
        let mut at_cap_der: Vec<Vec<u8>> = vec![issuing.der.clone()];
        for i in 0..31 {
            at_cap_der.push(new_ca(&format!("Root Hint Filler CA {i}")).der);
        }
        assert_eq!(at_cap_der.len(), MAX_ROOT_HINTS);
        let at_cap_refs: Vec<&[u8]> = at_cap_der.iter().map(Vec::as_slice).collect();
        let at_cap_anchors =
            TrustAnchors::from_der_bundle(&at_cap_refs).expect("32 real anchors must build");
        let hints_at_cap = hint_count_for(&issuing, at_cap_anchors);
        assert!(
            hints_at_cap > 0,
            "at exactly the cap, root hint subjects must still be sent"
        );

        // 33 anchors: one over the cap, hints must be cleared.
        let mut over_cap_der = at_cap_der;
        over_cap_der.push(new_ca("Root Hint Filler CA 31").der);
        assert_eq!(over_cap_der.len(), MAX_ROOT_HINTS + 1);
        let over_cap_refs: Vec<&[u8]> = over_cap_der.iter().map(Vec::as_slice).collect();
        let over_cap_anchors =
            TrustAnchors::from_der_bundle(&over_cap_refs).expect("33 real anchors must build");
        let hints_over_cap = hint_count_for(&issuing, over_cap_anchors);
        assert_eq!(
            hints_over_cap, 0,
            "one anchor over the cap, root hint subjects must be cleared"
        );
    }

    /// Runs a real in-memory handshake with client authentication `Optional` over `anchors`, using
    /// a custom `ResolvesClientCert` that records how many root hint subjects it was offered, and
    /// returns that count. The client always presents a certificate issued by `issuing`
    /// regardless of the hint list, which is what proves the handshake completes and the client
    /// still selects its certificate either way.
    fn hint_count_for(issuing: &CaFixture, anchors: TrustAnchors) -> usize {
        use std::sync::atomic::AtomicUsize;

        #[derive(Debug)]
        struct HintCapturingResolver {
            hints_len: Arc<AtomicUsize>,
            key: Arc<rustls::sign::CertifiedKey>,
        }
        impl rustls::client::ResolvesClientCert for HintCapturingResolver {
            fn resolve(
                &self,
                root_hint_subjects: &[&[u8]],
                _sigschemes: &[rustls::SignatureScheme],
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                self.hints_len
                    .store(root_hint_subjects.len(), Ordering::Relaxed);
                Some(Arc::clone(&self.key))
            }
            fn has_certs(&self) -> bool {
                true
            }
        }

        let auth = ClientAuth::Optional(anchors);
        let crls = empty_crls();
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            false,
            RevocationMode::Disabled,
            clock(),
        )
        .expect("build must succeed")
        .expect("Optional must produce a verifier");

        let (server_leaf_der, server_key_der) = client_leaf(issuing, "server.example.com");
        let provider = Arc::clone(crate::provider::provider().expect("provider installed"));
        let server_key = rustls::pki_types::PrivateKeyDer::try_from(server_key_der.as_slice())
            .expect("valid key")
            .clone_key();
        let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("protocol versions")
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(server_leaf_der)],
                server_key,
            )
            .expect("server config");

        let (client_leaf_der, client_key_der) = client_leaf(issuing, "hint-test-client");
        let client_key = rustls::pki_types::PrivateKeyDer::try_from(client_key_der.as_slice())
            .expect("valid key")
            .clone_key();
        let client_certified = rustls::sign::CertifiedKey::from_der(
            vec![rustls::pki_types::CertificateDer::from(client_leaf_der)],
            client_key,
            &provider,
        )
        .expect("valid client cert/key pair");
        let hints_len = Arc::new(AtomicUsize::new(usize::MAX));
        let resolver = Arc::new(HintCapturingResolver {
            hints_len: Arc::clone(&hints_len),
            key: Arc::new(client_certified),
        });

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(issuing.der.clone()))
            .expect("trust the server's own issuing CA");
        let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_client_cert_resolver(resolver);

        let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).expect("server conn");
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_cfg),
            "server.example.com".try_into().expect("server name"),
        )
        .expect("client conn");

        assert!(
            pump_handshake(&mut client, &mut server).is_none(),
            "the handshake must complete regardless of whether hints were sent"
        );

        hints_len.load(Ordering::Relaxed)
    }

    /// Drives two in-memory TLS endpoints through a handshake. Same shape used throughout this
    /// crate's own tests (`policy.rs`, `tests/handshake_resolver.rs`), duplicated rather than
    /// shared because each of those lives in a module this one cannot see.
    fn pump_handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) -> Option<std::io::Error> {
        for _ in 0..16 {
            let mut buf = Vec::new();
            if client.write_tls(&mut buf).is_ok()
                && !buf.is_empty()
                && let Err(e) = server
                    .read_tls(&mut buf.as_slice())
                    .map(|_| ())
                    .and_then(|()| {
                        server
                            .process_new_packets()
                            .map(|_| ())
                            .map_err(std::io::Error::other)
                    })
            {
                return Some(e);
            }
            let mut buf = Vec::new();
            if server.write_tls(&mut buf).is_ok()
                && !buf.is_empty()
                && let Err(e) = client
                    .read_tls(&mut buf.as_slice())
                    .map(|_| ())
                    .and_then(|()| {
                        client
                            .process_new_packets()
                            .map(|_| ())
                            .map_err(std::io::Error::other)
                    })
            {
                return Some(e);
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // verify_client_cert: revocation
    // -----------------------------------------------------------------------

    #[test]
    fn client_auth_no_crl_denies() {
        let fx = ca_fixture();
        let (leaf, _key) = client_leaf(fx, "no-crl-denies.example");
        let crls = crl_set_covering(other_ca_fixture(), &[]);
        let auth = ClientAuth::Required(anchors_for(fx));
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            false,
            RevocationMode::Enforced,
            clock(),
        )
        .expect("build")
        .expect("Required produces a verifier");
        let ee = end_entity(&leaf);
        let err = verifier
            .verify_client_cert(&ee, &[], now())
            .expect_err("no index for this issuer, and unknown status is not allowed");
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownRevocationStatus)
        );
        assert_eq!(verifier.stats().unknown_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn client_auth_no_crl_allowed() {
        let fx = ca_fixture();
        let (leaf, _key) = client_leaf(fx, "no-crl-allowed.example");
        let crls = crl_set_covering(other_ca_fixture(), &[]);
        let auth = ClientAuth::Required(anchors_for(fx));
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            true,
            RevocationMode::Enforced,
            clock(),
        )
        .expect("build")
        .expect("Required produces a verifier");
        let ee = end_entity(&leaf);
        assert!(verifier.verify_client_cert(&ee, &[], now()).is_ok());
        assert_eq!(verifier.stats().unknown_allowed.load(Ordering::Relaxed), 1);
        assert_eq!(verifier.stats().accepted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn client_auth_leaf_revoked() {
        let fx = ca_fixture();
        let serial: &[u8] = &[0x11];
        let (leaf, _key) = client_leaf_with_serial(fx, "leaf-revoked.example", serial);
        let crls = crl_set_covering(fx, &[serial]);
        let auth = ClientAuth::Required(anchors_for(fx));
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            false,
            RevocationMode::Enforced,
            clock(),
        )
        .expect("build")
        .expect("Required produces a verifier");
        let ee = end_entity(&leaf);
        let err = verifier
            .verify_client_cert(&ee, &[], now())
            .expect_err("the leaf's own serial is on the CRL");
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked)
        );
        assert_eq!(verifier.stats().revoked_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn client_auth_intermediate_revoked() {
        let root = ca_fixture();
        let intermediate_serial: &[u8] = &[0x22];
        let intermediate =
            intermediate_ca_with_serial(root, "Revoked Intermediate", intermediate_serial);
        let (leaf, _key) = client_leaf(&intermediate, "leaf-under-revoked-intermediate.example");
        // Coverage is needed for BOTH issuers the chain crosses: the leaf's own issuer is the
        // intermediate (empty revoked list, so the leaf's own lookup does not itself deny), and
        // the intermediate's issuer is the root, whose index revokes the INTERMEDIATE's serial,
        // not the leaf's. Without `RevocationCheckDepth::Chain` this would pass.
        let empty: &[&[u8]] = &[];
        let revoked: &[&[u8]] = &[intermediate_serial];
        let crls = crl_set_covering_multi(&[(&intermediate, empty), (root, revoked)]);
        let auth = ClientAuth::Required(anchors_for(root));
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            false,
            RevocationMode::Enforced,
            clock(),
        )
        .expect("build")
        .expect("Required produces a verifier");
        let ee = end_entity(&leaf);
        let inter = chain(&[&intermediate.der]);
        let err = verifier
            .verify_client_cert(&ee, &inter, now())
            .expect_err("the intermediate's own serial is on the CRL");
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked)
        );
        assert_eq!(verifier.stats().revoked_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn client_auth_stale_crl_used() {
        let fx = ca_fixture();
        let (leaf, _key) = client_leaf(fx, "stale.example");
        let this_update = date_secs(2020, 1, 1);
        let next_update = this_update + 86_400;
        let crls = crl_set_covering_with_updates(fx, &[], this_update, next_update);

        // One hour past next_update, well within the default one-day stale grace.
        let stale_now_secs = next_update + 3_600;
        let auth = ClientAuth::Required(anchors_for(fx));
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            false,
            RevocationMode::Enforced,
            clock_at(stale_now_secs),
        )
        .expect("build")
        .expect("Required produces a verifier");
        let ee = end_entity(&leaf);
        let chain_now = UnixTime::since_unix_epoch(Duration::from_secs(stale_now_secs));
        assert!(
            verifier.verify_client_cert(&ee, &[], chain_now).is_ok(),
            "a stale but not yet expired CRL must still be USED, not treated as absent"
        );
        assert_eq!(verifier.stats().stale_crl_used.load(Ordering::Relaxed), 1);
        assert_eq!(verifier.stats().accepted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn client_auth_expired_crl_denied() {
        let fx = ca_fixture();
        let (leaf, _key) = client_leaf(fx, "expired.example");
        let this_update = date_secs(2020, 1, 1);
        let next_update = this_update + 86_400;
        let crls = crl_set_covering_with_updates(fx, &[], this_update, next_update);

        // Two days past next_update: past the default one-day stale grace.
        let expired_now_secs = next_update + 2 * 86_400;
        let auth = ClientAuth::Required(anchors_for(fx));
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            false,
            RevocationMode::Enforced,
            clock_at(expired_now_secs),
        )
        .expect("build")
        .expect("Required produces a verifier");
        let ee = end_entity(&leaf);
        let chain_now = UnixTime::since_unix_epoch(Duration::from_secs(expired_now_secs));
        let err = verifier
            .verify_client_cert(&ee, &[], chain_now)
            .expect_err("an expired CRL with unknown status disallowed must deny");
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownRevocationStatus)
        );
        assert_eq!(
            verifier.stats().expired_crl_denied.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn client_auth_malformed_chain_cert() {
        let fx = ca_fixture();
        // Depth 1: the leaf is signed DIRECTLY by the trust anchor, so rustls-webpki's path
        // builder can verify it without ever needing the extra, garbage "intermediate" supplied
        // alongside it. That is exactly the scenario this function's own doc names: the inner
        // verifier accepts, and OUR revocation loop is the only thing left standing between a
        // malformed chain element and a Bloom probe over garbage bytes.
        let (leaf, _key) = client_leaf(fx, "malformed-intermediate.example");
        let crls = crl_set_covering(fx, &[]);
        let auth = ClientAuth::Required(anchors_for(fx));
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            false,
            RevocationMode::Enforced,
            clock(),
        )
        .expect("build")
        .expect("Required produces a verifier");
        let ee = end_entity(&leaf);
        let garbage: &[u8] = b"this is not a certificate at all, just bytes";
        let inter = chain(&[garbage]);
        let result = verifier.verify_client_cert(&ee, &inter, now());
        let err = result.expect_err(
            "a chain element that cannot decode as far as the issuer must be refused, even if \
             rustls-webpki's own path building never needed to use it",
        );
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        );
        assert_eq!(
            verifier
                .stats()
                .malformed_chain_cert
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn client_auth_revocation_disabled_skips_check() {
        let fx = ca_fixture();
        let serial: &[u8] = &[0x2a];
        let (leaf, _key) = client_leaf_with_serial(fx, "revoked-but-disabled.example", serial);
        // This CRL DOES revoke the leaf's own serial; revocation:disabled must accept anyway.
        let crls = crl_set_covering(fx, &[serial]);
        let auth = ClientAuth::Required(anchors_for(fx));
        let verifier = IronClientVerifier::new(
            &auth,
            crls,
            default_crl_cfg(),
            false,
            RevocationMode::Disabled,
            clock(),
        )
        .expect("build")
        .expect("Required produces a verifier");
        let ee = end_entity(&leaf);
        assert!(
            verifier.verify_client_cert(&ee, &[], now()).is_ok(),
            "revocation: disabled must accept even a certificate that IS revoked; that is \
             exactly what the operator asked for"
        );
        assert_eq!(verifier.stats().accepted.load(Ordering::Relaxed), 1);
        assert_eq!(verifier.stats().revoked_denied.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn client_auth_chain_depth_cap_discovered() {
        const MAX_DEPTH_TO_TRY: usize = 32;
        let root = new_ca("Chain Depth Root CA");
        let mut built: Vec<CaFixture> = Vec::new();
        for i in 0..(MAX_DEPTH_TO_TRY - 1) {
            let parent = built.last().unwrap_or(&root);
            built.push(intermediate_ca(
                parent,
                &format!("Chain Depth Intermediate {i}"),
            ));
        }

        let anchors = TrustAnchors::from_der_bundle(&[&root.der]).expect("root anchors");
        let auth = ClientAuth::Required(anchors);
        let verifier = IronClientVerifier::new(
            &auth,
            empty_crls(),
            default_crl_cfg(),
            false,
            RevocationMode::Disabled,
            clock(),
        )
        .expect("build")
        .expect("Required produces a verifier");

        let mut discovered_depth: Option<usize> = None;
        let mut deepest_verified = 0usize;
        for depth in 1..=MAX_DEPTH_TO_TRY {
            let signer = if depth == 1 { &root } else { &built[depth - 2] };
            let (leaf_der, _key) = client_leaf(signer, &format!("depth-{depth}.example"));
            let intermediate_ders: Vec<&[u8]> = if depth <= 1 {
                Vec::new()
            } else {
                built[0..depth - 1]
                    .iter()
                    .rev()
                    .map(|c| c.der.as_slice())
                    .collect()
            };
            let ee = end_entity(&leaf_der);
            let inter = chain(&intermediate_ders);
            if verifier.verify_client_cert(&ee, &inter, now()).is_ok() {
                deepest_verified = depth;
            } else {
                discovered_depth = Some(depth);
                break;
            }
        }

        let cap = discovered_depth.unwrap_or_else(|| {
            panic!(
                "rustls-webpki's compiled-in intermediate cap was not found by depth \
                 {MAX_DEPTH_TO_TRY}; every depth up to the ceiling verified successfully"
            )
        });
        #[allow(
            clippy::print_stdout,
            reason = "the issue's own acceptance criterion requires the discovered depth be \
                      visible in CI output, since rustls-webpki's cap is a private detail of the \
                      pinned version rather than a constant this test may assert against directly"
        )]
        {
            println!("discovered rustls-webpki chain depth cap: rejects starting at depth {cap}");
        }
        assert!(
            cap >= 3,
            "the discovered cap {cap} is too shallow to be meaningful"
        );
        assert_eq!(
            deepest_verified,
            cap - 1,
            "every depth shallower than the discovered cap must have verified"
        );
        // Revocation is disabled for this verifier and the loop that could panic never runs, so
        // the rejection at `cap` can only have come from the inner (rustls-webpki) verifier.
        assert_eq!(
            verifier.stats().accepted.load(Ordering::Relaxed),
            u64::try_from(deepest_verified).unwrap_or(u64::MAX)
        );
    }

    #[test]
    fn client_auth_ticketer_context_matches_trust_bundle() {
        let anchors_a = anchors_for(ca_fixture());
        let anchors_b = anchors_for(other_ca_fixture());
        assert_ne!(
            anchors_a.id(),
            anchors_b.id(),
            "fixture bug: two distinct CAs must have distinct trust-bundle ids"
        );

        let nonces: Arc<dyn crate::ticket::NonceSource> = Arc::new(RandNonceSource);
        let ticketer_a = ClusterTicketer::new(
            TicketRoot::new([7u8; 32]),
            anchors_a.id(),
            21_600,
            clock(),
            Arc::clone(&nonces),
        );
        let ticketer_b = ClusterTicketer::new(
            TicketRoot::new([7u8; 32]),
            anchors_b.id(),
            21_600,
            clock(),
            Arc::clone(&nonces),
        );
        let ticketer_none = ClusterTicketer::new(
            TicketRoot::new([7u8; 32]),
            [0u8; 16],
            21_600,
            clock(),
            nonces,
        );

        let plaintext = b"resumption-secret-material";
        let ticket_a = ticketer_a.encrypt(plaintext).expect("encrypt must succeed");
        assert!(ticketer_a.decrypt(&ticket_a).is_some());
        assert!(
            ticketer_b.decrypt(&ticket_a).is_none(),
            "a ticket issued under one trust bundle's context must not decrypt under another's"
        );
        assert!(
            ticketer_none.decrypt(&ticket_a).is_none(),
            "nor under the context-free (ClientAuthKind::None) ticketer"
        );

        let ticket_none = ticketer_none
            .encrypt(plaintext)
            .expect("encrypt must succeed");
        assert!(ticketer_a.decrypt(&ticket_none).is_none());
        assert!(ticketer_b.decrypt(&ticket_none).is_none());
    }

    // -----------------------------------------------------------------------
    // cert_serial_and_issuer
    // -----------------------------------------------------------------------

    #[test]
    fn cert_serial_and_issuer_extracts_both() {
        let fx = ca_fixture();
        let serial: &[u8] = &[0x7a, 0x01];
        let (leaf, _key) = client_leaf_with_serial(fx, "extract-both.example", serial);
        let (got_serial, got_issuer) =
            cert_serial_and_issuer(&leaf).expect("a well formed certificate must decode");
        assert_eq!(got_serial, serial);
        assert!(!got_issuer.is_empty());
        let crls = crl_set_covering(fx, &[]);
        assert!(
            crls.for_issuer(got_issuer).is_some(),
            "the extracted issuer span must match a CrlSet index built over the same CA"
        );
    }

    #[test]
    fn cert_serial_and_issuer_strips_leading_zero() {
        let fx = ca_fixture();
        // A serial whose top bit is set forces DER to prepend a 0x00 sign-disambiguation byte.
        // rcgen's writer (`yasna::write_bigint_bytes`) strips every leading zero and then adds
        // back exactly one, so this certificate's on-wire serial content octets are `[0x00,
        // 0x80]`; `cert_serial_and_issuer` must return `[0x80]` once its own `normalize_serial`
        // strips that byte back off.
        let serial: &[u8] = &[0x80];
        let (leaf, _key) = client_leaf_with_serial(fx, "leading-zero.example", serial);
        let (got_serial, _issuer) =
            cert_serial_and_issuer(&leaf).expect("a well formed certificate must decode");
        assert_eq!(
            got_serial,
            &[0x80u8][..],
            "the leading sign-disambiguation zero must be stripped"
        );
    }

    #[test]
    fn cert_serial_and_issuer_rejects_truncated() {
        let fx = ca_fixture();
        let (leaf, _key) = client_leaf(fx, "truncated.example");
        #[allow(
            clippy::integer_division,
            reason = "test fixture arithmetic over a length this test computed itself, not \
                      attacker-controlled input; halving is exactly the truncation point wanted"
        )]
        let half = leaf.len() / 2;
        assert!(
            cert_serial_and_issuer(&leaf[..half]).is_none(),
            "a certificate truncated to half its length cannot decode as far as the issuer"
        );
    }

    // -----------------------------------------------------------------------
    // Property test
    // -----------------------------------------------------------------------

    proptest! {
        // Measured: see the PR body for the observed case count and wall time.
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn prop_serial_normalization_agrees_with_crl(
            raw in proptest::collection::vec(any::<u8>(), 1..=20usize),
            leading_zeros in 0..=4usize,
        ) {
            // A serial of 1 to 20 bytes with 0 to 4 leading zero octets, matching #123's own
            // property generator shape. rcgen's DER writer canonicalizes (strips every leading
            // zero, then adds back exactly one if the remaining high bit is set) before either
            // the certificate or the CRL is encoded, so both sides converge on the same on-wire
            // bytes regardless of how many extra zeros this generator prepends. What the
            // property proves is that certificate-side extraction (this issue) and CRL-side
            // lookup (#123) agree on whatever that canonical form turns out to be, across a
            // random spread of serial VALUES rather than one hand-picked one.
            let mut padded = vec![0x00u8; leading_zeros];
            padded.extend_from_slice(&raw);

            let fx = ca_fixture();
            let (leaf, _key) = client_leaf_with_serial(fx, "prop.example", &padded);
            let crls = crl_set_covering(fx, &[&padded]);

            let (serial, issuer) = cert_serial_and_issuer(&leaf)
                .expect("a real rcgen-issued certificate must decode this far");
            let idx = crls.for_issuer(issuer).expect("the CrlSet was built over the same CA");
            prop_assert!(idx.is_revoked(serial));
        }
    }
}
