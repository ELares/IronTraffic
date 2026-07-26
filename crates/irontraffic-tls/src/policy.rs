// SPDX-License-Identifier: MIT OR Apache-2.0

//! The compiled, validated TLS protocol policy for one listener.
//!
//! Exactly three named profiles (`modern`, `intermediate`, `legacy`), server preference cipher
//! ordering, the post-quantum hybrid key exchange default for inbound connections, and the ALPN
//! list. There is no per-suite, per-group, or per-version knob: the set of things rustls can be
//! configured to do insecurely is already empty, and this module does not add one.

use std::sync::Arc;

/// Operator-facing TLS policy for one listener.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TlsPolicyConfig {
    /// Named profile. Default `intermediate`.
    #[serde(default)]
    pub profile: TlsProfile,
    /// ALPN protocols in server preference order. Default `["h2", "http/1.1"]`.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Post-quantum hybrid key exchange preference for inbound connections.
    /// Default `prefer`.
    #[serde(default)]
    pub post_quantum: PostQuantumConfig,
    /// Refuse clients that advertise no ECDSA signature scheme when an ECDSA credential exists
    /// for the requested name. Default false.
    #[serde(default)]
    pub require_ecdsa_capable_clients: bool,
}

/// The serde default for `TlsPolicyConfig::alpn`: `["h2", "http/1.1"]`.
fn default_alpn() -> Vec<String> {
    vec!["h2".to_owned(), "http/1.1".to_owned()]
}

/// Named protocol profile.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum TlsProfile {
    /// TLS 1.3 only.
    Modern,
    /// TLS 1.3 and TLS 1.2. The default.
    #[default]
    Intermediate,
    /// Rejected at compile time. Exists so the error message can point at the documentation
    /// instead of the operator guessing that the key is misspelled.
    Legacy,
}

/// Inbound post-quantum preference as configured.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PostQuantumConfig {
    /// Prefer X25519MLKEM768 when the client offers it. The default.
    #[default]
    Prefer,
    /// Do not offer hybrid key exchange.
    Off,
}

/// Post-quantum state after resolving the configuration against the compiled provider.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PostQuantum {
    /// Hybrid preferred and available.
    Preferred,
    /// Hybrid available but disabled by configuration.
    Disabled,
    /// This build has no ML-KEM implementation (a `crypto-ring` build).
    Unavailable,
}

/// One validated ALPN protocol identifier: 1 to 255 bytes, no NUL.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AlpnProtocol(Box<[u8]>);

/// Compiled protocol policy for one listener. Immutable.
#[derive(Clone, Debug)]
pub struct TlsPolicy {
    profile: TlsProfile,
    alpn: Box<[AlpnProtocol]>,
    post_quantum: PostQuantum,
    require_ecdsa_capable_clients: bool,
}

/// Why a TLS policy failed to compile.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PolicyError {
    /// The `legacy` profile was requested.
    LegacyProfile,
    /// `acme-tls/1` appeared in a listener ALPN list.
    AlpnAcmeReserved,
    /// An ALPN entry was empty or longer than 255 bytes.
    AlpnLength,
    /// An ALPN entry contained a byte outside printable ASCII.
    AlpnByte,
    /// An ALPN entry appeared twice.
    AlpnDuplicate,
    /// More than 64 ALPN entries.
    AlpnTooMany,
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PolicyError::LegacyProfile => "the legacy TLS profile is not supported: IronTraffic implements TLS 1.3 and TLS 1.2 only, and has no CBC, RC4, static RSA, compression or renegotiation code path at all; see docs/tls/PROFILES.md",
            PolicyError::AlpnAcmeReserved => "acme-tls/1 is reserved for the TLS-ALPN-01 challenge and may not appear in a listener ALPN list",
            PolicyError::AlpnLength => "an ALPN protocol identifier must be 1 to 255 bytes",
            PolicyError::AlpnByte => "an ALPN protocol identifier must contain only printable ASCII (0x20 to 0x7e)",
            PolicyError::AlpnDuplicate => "an ALPN protocol identifier appeared twice",
            PolicyError::AlpnTooMany => "a listener may declare at most 64 ALPN protocol identifiers",
        })
    }
}

impl std::error::Error for PolicyError {}

impl AlpnProtocol {
    /// Validate and wrap one protocol identifier.
    ///
    /// # Errors
    /// `PolicyError::AlpnLength`, `PolicyError::AlpnByte`, or `PolicyError::AlpnAcmeReserved`.
    pub fn new(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes == b"acme-tls/1" {
            return Err(PolicyError::AlpnAcmeReserved);
        }
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(PolicyError::AlpnLength);
        }
        if bytes.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
            return Err(PolicyError::AlpnByte);
        }
        Ok(Self(Box::from(bytes)))
    }

    /// The identifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// `b"h2"`.
    #[must_use]
    pub fn h2() -> Self {
        Self(Box::from(b"h2".as_slice()))
    }

    /// `b"http/1.1"`.
    #[must_use]
    pub fn http11() -> Self {
        Self(Box::from(b"http/1.1".as_slice()))
    }
}

/// Resolve the configured post-quantum preference against the compiled provider. Shared by
/// `TlsPolicy::compile`, `TlsPolicy::default_https`, and `TlsPolicy::passthrough` so invariant 6
/// (`PostQuantum::Preferred` implies `post_quantum_available()`) holds for every constructor, not
/// only for `compile`.
fn resolve_post_quantum(cfg: PostQuantumConfig) -> PostQuantum {
    if !crate::post_quantum_available() {
        PostQuantum::Unavailable
    } else if cfg == PostQuantumConfig::Off {
        PostQuantum::Disabled
    } else {
        PostQuantum::Preferred
    }
}

impl TlsPolicy {
    /// Compile and validate an operator-supplied policy.
    ///
    /// # Errors
    /// Any `PolicyError`.
    pub fn compile(cfg: &TlsPolicyConfig) -> Result<Self, PolicyError> {
        if cfg.profile == TlsProfile::Legacy {
            return Err(PolicyError::LegacyProfile);
        }
        // Checked first, before the per-entry validation and the duplicate scan, so a
        // pathological list costs one comparison rather than an O(a^2) scan: see invariant 7.
        if cfg.alpn.len() > 64 {
            return Err(PolicyError::AlpnTooMany);
        }
        let mut alpn: Vec<AlpnProtocol> = Vec::with_capacity(cfg.alpn.len());
        for entry in &cfg.alpn {
            let candidate = AlpnProtocol::new(entry.as_bytes())?;
            if alpn.contains(&candidate) {
                return Err(PolicyError::AlpnDuplicate);
            }
            alpn.push(candidate);
        }
        Ok(Self {
            profile: cfg.profile,
            alpn: alpn.into_boxed_slice(),
            post_quantum: resolve_post_quantum(cfg.post_quantum),
            require_ecdsa_capable_clients: cfg.require_ecdsa_capable_clients,
        })
    }

    /// The default policy: `intermediate`, `["h2", "http/1.1"]`, post-quantum preferred.
    ///
    /// Post-quantum is resolved against the compiled provider exactly as `compile` resolves it,
    /// so on a `crypto-ring` build `post_quantum()` is `PostQuantum::Unavailable` rather than
    /// `Preferred`. Invariant 6 has to hold for every constructor, not only for `compile`.
    #[must_use]
    pub fn default_https() -> Self {
        Self {
            profile: TlsProfile::Intermediate,
            alpn: vec![AlpnProtocol::h2(), AlpnProtocol::http11()].into_boxed_slice(),
            post_quantum: resolve_post_quantum(PostQuantumConfig::Prefer),
            require_ecdsa_capable_clients: false,
        }
    }

    /// The passthrough policy: `intermediate`, empty ALPN, post-quantum resolved as in
    /// `default_https`.
    #[must_use]
    pub fn passthrough() -> Self {
        Self {
            profile: TlsProfile::Intermediate,
            alpn: Vec::new().into_boxed_slice(),
            post_quantum: resolve_post_quantum(PostQuantumConfig::Prefer),
            require_ecdsa_capable_clients: false,
        }
    }

    /// The profile.
    #[must_use]
    pub fn profile(&self) -> TlsProfile {
        self.profile
    }

    /// ALPN protocols in server preference order.
    #[must_use]
    pub fn alpn(&self) -> &[AlpnProtocol] {
        &self.alpn
    }

    /// Resolved post-quantum state.
    #[must_use]
    pub fn post_quantum(&self) -> PostQuantum {
        self.post_quantum
    }

    /// Whether to refuse clients that advertise no ECDSA scheme when an ECDSA credential exists.
    #[must_use]
    pub fn require_ecdsa_capable_clients(&self) -> bool {
        self.require_ecdsa_capable_clients
    }

    /// One-line, operator-facing summary for the startup log. The format is exactly
    ///
    /// ```text
    /// profile={modern|intermediate|legacy} alpn={comma-joined,or the literal "none" when empty} pq={preferred|disabled|unavailable} ecdsa-required={true|false}
    /// ```
    ///
    /// so `default_https()` on an aws-lc-rs build renders exactly
    /// `"profile=intermediate alpn=h2,http/1.1 pq=preferred ecdsa-required=false"`,
    /// and on a `crypto-ring` build exactly
    /// `"profile=intermediate alpn=h2,http/1.1 pq=unavailable ecdsa-required=false"`.
    /// `passthrough()` renders `alpn=none`. This string appears in the startup log and in a
    /// support bundle, so it is a contract and `summary_is_stable` asserts it byte for byte.
    #[must_use]
    pub fn summary(&self) -> String {
        let profile = match self.profile {
            TlsProfile::Modern => "modern",
            TlsProfile::Intermediate => "intermediate",
            TlsProfile::Legacy => "legacy",
        };
        let alpn = if self.alpn.is_empty() {
            "none".to_owned()
        } else {
            self.alpn
                .iter()
                .map(|protocol| String::from_utf8_lossy(protocol.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join(",")
        };
        let post_quantum = match self.post_quantum {
            PostQuantum::Preferred => "preferred",
            PostQuantum::Disabled => "disabled",
            PostQuantum::Unavailable => "unavailable",
        };
        format!(
            "profile={profile} alpn={alpn} pq={post_quantum} ecdsa-required={}",
            self.require_ecdsa_capable_clients
        )
    }

    /// Warnings to log once at startup. Currently exactly one condition: an HTTPS listener with an
    /// empty ALPN list, whose text is
    /// `"listener has an empty ALPN list: HTTP/2 will not be negotiated"`.
    #[must_use]
    pub fn startup_warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();
        if self.alpn.is_empty() {
            warnings.push("listener has an empty ALPN list: HTTP/2 will not be negotiated");
        }
        warnings
    }
}

/// `versions(TlsProfile::Modern)`.
#[allow(
    dead_code,
    reason = "read by `versions` below, called by cert-resolver-and-acme-challenge-map (#117), \
              which owns building the full ServerConfig; #117 is not in the tree yet, so in a \
              plain (non test) build this constant is reachable only from this crate's own \
              policy.rs tests"
)]
const MODERN_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
/// `versions(TlsProfile::Intermediate)`, TLS 1.3 first.
#[allow(
    dead_code,
    reason = "read by `versions` below, called by cert-resolver-and-acme-challenge-map (#117), \
              which owns building the full ServerConfig; #117 is not in the tree yet, so in a \
              plain (non test) build this constant is reachable only from this crate's own \
              policy.rs tests"
)]
const INTERMEDIATE_VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// The protocol versions this profile enables, in the form rustls's builder wants.
#[allow(
    dead_code,
    reason = "called by cert-resolver-and-acme-challenge-map (#117), which owns building the \
              full ServerConfig from a TlsPolicy plus its certificate resolver; #117 is not in \
              the tree yet, so this function has no caller outside this crate's own policy.rs \
              tests in a plain (non test) build"
)]
pub(crate) fn versions(
    profile: TlsProfile,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match profile {
        TlsProfile::Modern => MODERN_VERSIONS,
        // `Legacy` is rejected by `TlsPolicy::compile` before any `TlsPolicy` value can be
        // built with it, so this value is never actually served to a listener. Returning the
        // `Intermediate` value here rather than panicking means a configuration bug can never
        // turn into a process wide denial of service reachable from configuration.
        TlsProfile::Intermediate | TlsProfile::Legacy => INTERMEDIATE_VERSIONS,
    }
}

/// Apply every field that is settable after the builder has produced a `ServerConfig`.
#[allow(
    dead_code,
    reason = "called by cert-resolver-and-acme-challenge-map (#117), which owns building the \
              full ServerConfig from a TlsPolicy plus its certificate resolver; #117 is not in \
              the tree yet, so this function has no caller outside this crate's own policy.rs \
              tests in a plain (non test) build"
)]
pub(crate) fn apply_common(policy: &TlsPolicy, cfg: &mut rustls::ServerConfig) {
    // This allocates. It runs once per listener per configuration generation, not per connection.
    cfg.alpn_protocols = policy
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    cfg.ignore_client_order = true;
    // Early data is opt-in and is raised only by `early-data-policy-and-replay-filter` (#121).
    cfg.max_early_data_size = 0;
    cfg.send_half_rtt_data = false;
    // Already the rustls default; written out because it is the flag that hands the negotiated
    // traffic secrets to application code, and may be raised only for a listener with kTLS
    // enabled, which is not in this milestone.
    cfg.enable_secret_extraction = false;
    // Stateful resumption is rejected by design: a session cache is per node state that does not
    // cluster, and a resumed session carries the client authentication decision made under the
    // previous configuration. Resumption is delivered by the stateless `ClusterTicketer` in
    // `cluster-derived-session-ticketer` (#120); until that lands, the correct behaviour is no
    // resumption at all.
    cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
}

/// The provider a config for this post-quantum state should be built from.
///
/// Returns the process provider unchanged for `Preferred` and `Unavailable`, and a clone
/// with the hybrid group filtered out for `Disabled`. Takes the resolved `PostQuantum`
/// rather than a whole `TlsPolicy` because `upstream-tls-verification-and-identity` (#125)
/// needs the same filtered provider for a `ClientConfig`, where no `TlsPolicy` exists.
///
/// Returns `None` when no provider is installed, which is the same startup ordering bug
/// `crate::provider::provider` reports.
#[allow(
    dead_code,
    reason = "called by cert-resolver-and-acme-challenge-map (#117) for a ServerConfig and by \
              upstream-tls-verification-and-identity (#125) for a ClientConfig; neither sibling \
              issue is in the tree yet, so this function has no caller outside this crate's own \
              policy.rs tests in a plain (non test) build"
)]
pub(crate) fn provider_for(pq: PostQuantum) -> Option<Arc<rustls::crypto::CryptoProvider>> {
    let base = crate::provider::provider()?;
    if pq != PostQuantum::Disabled {
        return Some(Arc::clone(base));
    }
    Some(Arc::new(without_hybrid_group(base)))
}

/// The transformation `provider_for` applies for `PostQuantum::Disabled`: a clone of `provider`
/// with the post-quantum hybrid group removed, preserving the relative order of the groups that
/// remain (`Vec::retain` preserves order, which is what the filtered clone's ordering guarantee
/// rests on).
///
/// Deliberately a pure, provider instance scoped function rather than reading the process global
/// provider itself, so `post_quantum_off_filters_hybrid_group` can exercise this exact
/// transformation on a locally built provider without installing anything process wide: see that
/// test for why touching the process default here is something this crate's own tests must avoid.
fn without_hybrid_group(
    provider: &rustls::crypto::CryptoProvider,
) -> rustls::crypto::CryptoProvider {
    let mut filtered = provider.clone();
    filtered
        .kx_groups
        .retain(|group| group.name() != rustls::NamedGroup::X25519MLKEM768);
    filtered
}

#[cfg(test)]
mod tests {
    use super::{
        AlpnProtocol, PolicyError, PostQuantum, PostQuantumConfig, TlsPolicy, TlsPolicyConfig,
        TlsProfile, apply_common, default_alpn, versions, without_hybrid_group,
    };
    use serde::Deserialize;
    use std::sync::Arc;

    fn cfg_with_alpn(alpn: Vec<String>) -> TlsPolicyConfig {
        TlsPolicyConfig {
            profile: TlsProfile::Intermediate,
            alpn,
            post_quantum: PostQuantumConfig::Prefer,
            require_ecdsa_capable_clients: false,
        }
    }

    /// A `CryptoProvider` built directly from the compiled in provider constructor, independent
    /// of the process global default slot that `install_process_provider` populates.
    ///
    /// Tests that build a throwaway `ServerConfig`/`ClientConfig` use
    /// `builder_with_provider(test_provider())` rather than `builder_with_protocol_versions`,
    /// because the latter silently installs a process default from rustls's own crate feature
    /// fallback the first time it runs with none installed
    /// (`CryptoProvider::get_default_or_install_from_crate_features`). That silent install races
    /// `provider::tests::provider_lifecycle`, whose first assertions require that nothing has
    /// touched the process default yet; building every throwaway config from a locally owned
    /// provider value keeps these tests from touching that global slot at all.
    fn test_provider() -> Arc<rustls::crypto::CryptoProvider> {
        #[cfg(any(feature = "crypto-aws-lc-rs", feature = "crypto-fips"))]
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        #[cfg(feature = "crypto-ring")]
        let provider = rustls::crypto::ring::default_provider();
        Arc::new(provider)
    }

    /// Fixture: an rcgen self-signed ECDSA P-256 leaf certificate for the given names, returned
    /// as `(certificate DER, private key DER)` so no key material is committed.
    fn gen_leaf(alg: &'static rcgen::SignatureAlgorithm, sans: &[&str]) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate_for(alg).expect("keypair generation");
        let names: Vec<String> = sans.iter().map(|name| (*name).to_owned()).collect();
        let params = rcgen::CertificateParams::new(names).expect("certificate params");
        let cert = params.self_signed(&key).expect("self signed certificate");
        (cert.der().to_vec(), key.serialize_der())
    }

    /// Drives two in-memory TLS endpoints through a handshake, returning the first error either
    /// side reports, or `None` if both complete. 16 rounds is far more than a handshake needs and
    /// bounds the loop.
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

    #[test]
    fn default_https_is_intermediate_h2_http11() {
        let policy = TlsPolicy::default_https();
        assert_eq!(policy.profile(), TlsProfile::Intermediate);
        assert_eq!(
            policy.alpn().to_vec(),
            vec![AlpnProtocol::h2(), AlpnProtocol::http11()]
        );
        let expected = if crate::post_quantum_available() {
            PostQuantum::Preferred
        } else {
            PostQuantum::Unavailable
        };
        assert_eq!(policy.post_quantum(), expected);
    }

    #[test]
    fn passthrough_has_empty_alpn() {
        let policy = TlsPolicy::passthrough();
        assert_eq!(policy.profile(), TlsProfile::Intermediate);
        assert!(policy.alpn().is_empty());
    }

    #[test]
    fn legacy_profile_rejected_with_docs_pointer() {
        let cfg = cfg_with_alpn(default_alpn());
        let cfg = TlsPolicyConfig {
            profile: TlsProfile::Legacy,
            ..cfg
        };
        let err = TlsPolicy::compile(&cfg).unwrap_err();
        assert_eq!(err, PolicyError::LegacyProfile);
        assert!(err.to_string().contains("docs/tls/PROFILES.md"));
    }

    #[test]
    fn alpn_acme_reserved_rejected() {
        let cfg = cfg_with_alpn(vec!["acme-tls/1".to_owned()]);
        assert_eq!(
            TlsPolicy::compile(&cfg).unwrap_err(),
            PolicyError::AlpnAcmeReserved
        );
    }

    #[test]
    fn alpn_duplicate_rejected() {
        let cfg = cfg_with_alpn(vec!["h2".to_owned(), "h2".to_owned()]);
        assert_eq!(
            TlsPolicy::compile(&cfg).unwrap_err(),
            PolicyError::AlpnDuplicate
        );
    }

    #[test]
    fn alpn_len_255_ok_256_rejected() {
        let ok_cfg = cfg_with_alpn(vec!["a".repeat(255)]);
        assert!(TlsPolicy::compile(&ok_cfg).is_ok());

        let bad_cfg = cfg_with_alpn(vec!["a".repeat(256)]);
        assert_eq!(
            TlsPolicy::compile(&bad_cfg).unwrap_err(),
            PolicyError::AlpnLength
        );
    }

    #[test]
    fn alpn_empty_entry_rejected() {
        let cfg = cfg_with_alpn(vec![String::new()]);
        assert_eq!(
            TlsPolicy::compile(&cfg).unwrap_err(),
            PolicyError::AlpnLength
        );
    }

    #[test]
    fn alpn_non_printable_rejected() {
        let cfg = cfg_with_alpn(vec!["h2\n".to_owned()]);
        assert_eq!(TlsPolicy::compile(&cfg).unwrap_err(), PolicyError::AlpnByte);
        let cfg_nul = cfg_with_alpn(vec!["h2\0".to_owned()]);
        assert_eq!(
            TlsPolicy::compile(&cfg_nul).unwrap_err(),
            PolicyError::AlpnByte
        );
    }

    #[test]
    fn alpn_65_entries_rejected() {
        let alpn: Vec<String> = (0..65).map(|i| format!("proto-{i}")).collect();
        let cfg = cfg_with_alpn(alpn);
        assert_eq!(
            TlsPolicy::compile(&cfg).unwrap_err(),
            PolicyError::AlpnTooMany
        );
    }

    #[test]
    fn empty_alpn_produces_startup_warning() {
        let cfg = cfg_with_alpn(Vec::new());
        let policy = TlsPolicy::compile(&cfg).expect("an empty ALPN list is a valid configuration");
        assert_eq!(
            policy.startup_warnings(),
            vec!["listener has an empty ALPN list: HTTP/2 will not be negotiated"]
        );
    }

    #[cfg(any(feature = "crypto-aws-lc-rs", feature = "crypto-fips"))]
    #[test]
    fn post_quantum_preferred_on_aws_lc() {
        let cfg = cfg_with_alpn(default_alpn());
        let policy = TlsPolicy::compile(&cfg).expect("a default shaped configuration is valid");
        assert_eq!(policy.post_quantum(), PostQuantum::Preferred);
    }

    #[cfg(feature = "crypto-ring")]
    #[test]
    fn post_quantum_unavailable_on_ring() {
        let cfg = cfg_with_alpn(default_alpn());
        let policy = TlsPolicy::compile(&cfg).expect("a default shaped configuration is valid");
        assert_eq!(policy.post_quantum(), PostQuantum::Unavailable);
    }

    #[test]
    fn post_quantum_off_filters_hybrid_group() {
        // A locally built provider, not the process default: this crate's tests must never
        // install a process wide provider themselves (see `test_provider`'s doc comment), so
        // this exercises the exact transformation `provider_for` applies for
        // `PostQuantum::Disabled` on a provider value this test owns outright.
        let provider = test_provider();
        let unfiltered_names: Vec<_> = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();

        let filtered = without_hybrid_group(&provider);
        let filtered_names: Vec<_> = filtered
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();

        assert!(!filtered_names.contains(&rustls::NamedGroup::X25519MLKEM768));
        let expected: Vec<_> = unfiltered_names
            .iter()
            .copied()
            .filter(|name| *name != rustls::NamedGroup::X25519MLKEM768)
            .collect();
        assert_eq!(filtered_names, expected);
    }

    #[test]
    fn unknown_config_field_rejected() {
        let pairs = vec![("profil", "modern")];
        let deserializer =
            serde::de::value::MapDeserializer::<_, serde::de::value::Error>::new(pairs.into_iter());
        let result = TlsPolicyConfig::deserialize(deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn profile_case_sensitive() {
        let pairs = vec![("profile", "MODERN")];
        let deserializer =
            serde::de::value::MapDeserializer::<_, serde::de::value::Error>::new(pairs.into_iter());
        let err = TlsPolicyConfig::deserialize(deserializer).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("modern"));
        assert!(message.contains("intermediate"));
        assert!(message.contains("legacy"));
    }

    #[test]
    fn apply_common_sets_every_field() {
        let (leaf_der, key_der) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["t.example"]);
        let chain = vec![rustls::pki_types::CertificateDer::from(leaf_der)];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der.as_slice())
            .expect("key")
            .clone_key();

        let mut server_cfg = rustls::ServerConfig::builder_with_provider(test_provider())
            .with_protocol_versions(versions(TlsProfile::Intermediate))
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        apply_common(&TlsPolicy::default_https(), &mut server_cfg);

        assert!(server_cfg.ignore_client_order);
        assert_eq!(server_cfg.max_early_data_size, 0);
        assert!(!server_cfg.send_half_rtt_data);
        assert!(!server_cfg.enable_secret_extraction);
        assert_eq!(
            server_cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn modern_profile_refuses_tls12_client() {
        // Fixture: rcgen self-signed leaf for "t.example".
        let (leaf_der, key_der) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["t.example"]);
        let chain = vec![rustls::pki_types::CertificateDer::from(leaf_der.clone())];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der.as_slice())
            .expect("key")
            .clone_key();

        let mut server_cfg = rustls::ServerConfig::builder_with_provider(test_provider())
            .with_protocol_versions(versions(TlsProfile::Modern))
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        apply_common(&TlsPolicy::default_https(), &mut server_cfg);

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(leaf_der))
            .expect("root");
        let client_cfg = rustls::ClientConfig::builder_with_provider(test_provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).expect("server conn");
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_cfg),
            "t.example".try_into().expect("server name"),
        )
        .expect("client conn");

        let err = pump_handshake(&mut client, &mut server);
        assert!(
            err.is_some(),
            "a TLS 1.2-only client must not complete a modern-profile handshake"
        );
    }

    #[test]
    fn summary_is_stable() {
        let expected = if crate::post_quantum_available() {
            "profile=intermediate alpn=h2,http/1.1 pq=preferred ecdsa-required=false"
        } else {
            "profile=intermediate alpn=h2,http/1.1 pq=unavailable ecdsa-required=false"
        };
        assert_eq!(TlsPolicy::default_https().summary(), expected);
        assert!(TlsPolicy::passthrough().summary().contains("alpn=none"));
    }

    #[test]
    fn no_stateful_resumption_without_ticketer() {
        let (leaf_der, key_der) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["t.example"]);
        let chain = vec![rustls::pki_types::CertificateDer::from(leaf_der.clone())];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der.as_slice())
            .expect("key")
            .clone_key();

        let mut server_cfg = rustls::ServerConfig::builder_with_provider(test_provider())
            .with_protocol_versions(versions(TlsProfile::Intermediate))
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        apply_common(&TlsPolicy::default_https(), &mut server_cfg);
        let server_cfg = Arc::new(server_cfg);

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(leaf_der))
            .expect("root");
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(test_provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        // First connection: a full handshake. Per `apply_common`'s `session_storage` change, no
        // ticket is ever issued for the client to resume with later.
        let mut server1 =
            rustls::ServerConnection::new(Arc::clone(&server_cfg)).expect("server conn 1");
        let mut client1 = rustls::ClientConnection::new(
            Arc::clone(&client_cfg),
            "t.example".try_into().expect("server name"),
        )
        .expect("client conn 1");
        assert!(
            pump_handshake(&mut client1, &mut server1).is_none(),
            "the first handshake must complete"
        );
        assert_eq!(server1.handshake_kind(), Some(rustls::HandshakeKind::Full));

        // Second connection, same `ClientConfig`, so its session store (if anything had landed
        // in it) would be consulted here. Still a full handshake: no server side session state
        // exists to resume from.
        let mut server2 =
            rustls::ServerConnection::new(Arc::clone(&server_cfg)).expect("server conn 2");
        let mut client2 = rustls::ClientConnection::new(
            Arc::clone(&client_cfg),
            "t.example".try_into().expect("server name"),
        )
        .expect("client conn 2");
        assert!(
            pump_handshake(&mut client2, &mut server2).is_none(),
            "the second handshake must complete"
        );
        assert_eq!(server2.handshake_kind(), Some(rustls::HandshakeKind::Full));
    }
}
