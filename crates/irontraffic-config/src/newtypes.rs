// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validating newtypes over the primitive fields of [`crate::model::BootstrapDoc`].
//!
//! Every constructor is a `TryFrom` implementation, so a value that exists is a
//! value that has already been checked: there is no separate "validate this
//! later" step for any of these types.

/// A field failed its own validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FieldError {
    /// The listener name is empty, too long, or has an illegal character.
    #[error(
        "listener name {found:?} is invalid: names are 1 to 63 bytes of [a-z0-9-], not starting or ending with '-'"
    )]
    ListenerName {
        /// The value that was rejected.
        found: String,
    },
    /// The bind address did not parse as `IP:PORT`.
    #[error(
        "bind address {found:?} is invalid: expected IP:PORT, for example 0.0.0.0:8080 or [::]:8080"
    )]
    BindAddr {
        /// The value that was rejected.
        found: String,
    },
    /// The upstream address did not parse as `IP:PORT`.
    #[error(
        "upstream address {found:?} is invalid: expected an IP literal with a port, for example 127.0.0.1:8080; hostnames are not supported in this version because the data plane has no asynchronous resolver"
    )]
    UpstreamAddr {
        /// The value that was rejected.
        found: String,
    },
    /// The backlog is 0 or above 65535.
    #[error("backlog {found} is out of range: expected 1 to 65535")]
    Backlog {
        /// The value that was rejected.
        found: u32,
    },
    /// The duration is 0 or above 24 hours.
    #[error("duration {found} ms is out of range: expected 1 to 86400000")]
    Millis {
        /// The value that was rejected.
        found: u32,
    },
}

/// A listener name: 1 to 63 bytes matching `[a-z0-9]([a-z0-9-]*[a-z0-9])?`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
#[schemars(
    with = "String",
    extend("pattern" = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", "maxLength" = 63)
)]
pub struct ListenerName(smol_str::SmolStr);

impl ListenerName {
    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// The single validator both `TryFrom` impls delegate to.
fn parse_listener_name(s: &str) -> Result<ListenerName, FieldError> {
    let bytes = s.as_bytes();
    let len_ok = !bytes.is_empty() && bytes.len() <= 63;
    let charset_ok = bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    let edges_ok = match (bytes.first(), bytes.last()) {
        (Some(first), Some(last)) => *first != b'-' && *last != b'-',
        (None, _) | (_, None) => false,
    };
    if len_ok && charset_ok && edges_ok {
        Ok(ListenerName(smol_str::SmolStr::new(s)))
    } else {
        Err(FieldError::ListenerName {
            found: s.to_owned(),
        })
    }
}

impl TryFrom<String> for ListenerName {
    type Error = FieldError;

    /// # Errors
    /// [`FieldError::ListenerName`] when the value is empty, longer than 63
    /// bytes, contains a character outside `[a-z0-9-]`, or starts or ends
    /// with `-`.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        parse_listener_name(&value)
    }
}

impl TryFrom<&str> for ListenerName {
    type Error = FieldError;

    /// # Errors
    /// [`FieldError::ListenerName`] when the value is empty, longer than 63
    /// bytes, contains a character outside `[a-z0-9-]`, or starts or ends
    /// with `-`.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_listener_name(value)
    }
}

impl std::fmt::Display for ListenerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl From<ListenerName> for String {
    fn from(value: ListenerName) -> Self {
        value.0.as_str().to_owned()
    }
}

/// An address to bind a listener to, parsed from `"0.0.0.0:8080"` or `"[::]:8080"`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct BindAddr(std::net::SocketAddr);

impl BindAddr {
    /// The parsed address.
    #[must_use]
    pub fn socket_addr(self) -> std::net::SocketAddr {
        self.0
    }

    /// The one canonical spelling used for every comparison and every map key.
    ///
    /// `0.0.0.0:80` for IPv4 and `[::]:80` for IPv6. Two configurations that
    /// name the same endpoint produce byte-identical keys, which is what
    /// keeps a future file-descriptor handoff from re-binding instead of
    /// inheriting.
    #[must_use]
    pub fn canonical_key(self) -> String {
        self.0.to_string()
    }
}

fn parse_bind_addr(s: &str) -> Result<BindAddr, FieldError> {
    s.parse::<std::net::SocketAddr>()
        .map(BindAddr)
        .map_err(|_parse_error| FieldError::BindAddr {
            found: s.to_owned(),
        })
}

impl TryFrom<String> for BindAddr {
    type Error = FieldError;

    /// # Errors
    /// [`FieldError::BindAddr`] when the value does not parse as `IP:PORT`.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        parse_bind_addr(&value)
    }
}

impl TryFrom<&str> for BindAddr {
    type Error = FieldError;

    /// # Errors
    /// [`FieldError::BindAddr`] when the value does not parse as `IP:PORT`.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_bind_addr(value)
    }
}

impl std::fmt::Display for BindAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<BindAddr> for String {
    fn from(value: BindAddr) -> Self {
        value.0.to_string()
    }
}

/// The single upstream socket address for this version. Must be an IP literal
/// with a port; hostnames are rejected because the data plane has no
/// asynchronous resolver.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct UpstreamAddr(std::net::SocketAddr);

impl UpstreamAddr {
    /// The parsed address.
    #[must_use]
    pub fn socket_addr(self) -> std::net::SocketAddr {
        self.0
    }
}

fn parse_upstream_addr(s: &str) -> Result<UpstreamAddr, FieldError> {
    s.parse::<std::net::SocketAddr>()
        .map(UpstreamAddr)
        .map_err(|_parse_error| FieldError::UpstreamAddr {
            found: s.to_owned(),
        })
}

impl TryFrom<String> for UpstreamAddr {
    type Error = FieldError;

    /// # Errors
    /// [`FieldError::UpstreamAddr`] when the value does not parse as an IP
    /// literal with a port.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        parse_upstream_addr(&value)
    }
}

impl TryFrom<&str> for UpstreamAddr {
    type Error = FieldError;

    /// # Errors
    /// [`FieldError::UpstreamAddr`] when the value does not parse as an IP
    /// literal with a port.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_upstream_addr(value)
    }
}

impl std::fmt::Display for UpstreamAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<UpstreamAddr> for String {
    fn from(value: UpstreamAddr) -> Self {
        value.0.to_string()
    }
}

/// A `listen(2)` backlog, 1 to 65535.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(try_from = "u32", into = "u32")]
#[schemars(with = "u32", extend("minimum" = 1, "maximum" = 65535))]
pub struct Backlog(u32);

impl Backlog {
    /// The smallest legal backlog. Used as the total fallback in the serde
    /// default functions in `model.rs`, which can never actually reach it:
    /// their inputs are constants inside the valid range.
    pub const MIN: Backlog = Backlog(1);

    /// The value.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Backlog {
    type Error = FieldError;

    /// # Errors
    /// [`FieldError::Backlog`] when `value` is 0 or greater than 65535.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if (1..=65_535).contains(&value) {
            Ok(Backlog(value))
        } else {
            Err(FieldError::Backlog { found: value })
        }
    }
}

impl std::fmt::Display for Backlog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Backlog> for u32 {
    fn from(value: Backlog) -> Self {
        value.0
    }
}

/// A duration in milliseconds, 1 to 86,400,000 (24 hours).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "u32", into = "u32")]
#[schemars(with = "u32", extend("minimum" = 1, "maximum" = 86_400_000))]
pub struct Millis(u32);

impl Millis {
    /// The smallest legal value: 1 millisecond. Used as the total fallback in
    /// the serde default functions in `model.rs`, which can never actually
    /// reach it: their inputs are constants inside the valid range.
    pub const MIN: Millis = Millis(1);

    /// The value in milliseconds.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }

    /// The value as a `std::time::Duration`, for handing to an I/O deadline.
    #[must_use]
    pub fn as_duration(self) -> std::time::Duration {
        std::time::Duration::from_millis(u64::from(self.0))
    }
}

impl TryFrom<u32> for Millis {
    type Error = FieldError;

    /// # Errors
    /// [`FieldError::Millis`] when `value` is 0 or greater than 86,400,000.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if (1..=86_400_000).contains(&value) {
            Ok(Millis(value))
        } else {
            Err(FieldError::Millis { found: value })
        }
    }
}

impl std::fmt::Display for Millis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Millis> for u32 {
    fn from(value: Millis) -> Self {
        value.0
    }
}

/// The serde-facing spelling of [`irontraffic_runtime::RuntimeMode`]. Converts to
/// that type, which deliberately has no serde derive so the runtime crate stays
/// free of serde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum ModeSpec {
    /// One multi-threaded work-stealing runtime. The default.
    #[default]
    Balanced,
    /// Pinned shared-nothing runtimes. Refused at runtime build time in this version.
    Shard,
}

impl From<ModeSpec> for irontraffic_runtime::RuntimeMode {
    fn from(value: ModeSpec) -> Self {
        match value {
            ModeSpec::Balanced => irontraffic_runtime::RuntimeMode::Balanced,
            ModeSpec::Shard => irontraffic_runtime::RuntimeMode::Shard,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{Backlog, BindAddr, FieldError, ListenerName, Millis, ModeSpec, UpstreamAddr};

    // Not one of the 23 tests the issue names, added on top of them. Mutation
    // testing this crate found that every OTHER test reaches `FieldError`'s
    // `Display` only through `.contains(...)` on a fragment (or not at all for
    // `ListenerName`/`BindAddr`/`Backlog`/`Millis`), so a wrong number baked
    // into a `#[error("...")]` string (for example the upper bound in the
    // `Millis` or `ListenerName` message) compiles, passes every named test,
    // and ships a misleading diagnostic to an operator. This test pins the
    // exact rendered text for every variant so that class of typo fails here.
    #[test]
    fn field_error_messages_match_exactly() {
        assert_eq!(
            FieldError::ListenerName {
                found: "Web".to_owned()
            }
            .to_string(),
            "listener name \"Web\" is invalid: names are 1 to 63 bytes of [a-z0-9-], not starting or ending with '-'"
        );
        assert_eq!(
            FieldError::BindAddr {
                found: "8080".to_owned()
            }
            .to_string(),
            "bind address \"8080\" is invalid: expected IP:PORT, for example 0.0.0.0:8080 or [::]:8080"
        );
        assert_eq!(
            FieldError::UpstreamAddr {
                found: "example.com:80".to_owned()
            }
            .to_string(),
            "upstream address \"example.com:80\" is invalid: expected an IP literal with a port, for example 127.0.0.1:8080; hostnames are not supported in this version because the data plane has no asynchronous resolver"
        );
        assert_eq!(
            FieldError::Backlog { found: 0 }.to_string(),
            "backlog 0 is out of range: expected 1 to 65535"
        );
        assert_eq!(
            FieldError::Millis { found: 0 }.to_string(),
            "duration 0 ms is out of range: expected 1 to 86400000"
        );
    }

    #[test]
    fn listener_name_accepts_legal_forms() {
        assert!(ListenerName::try_from("web").is_ok());
        assert!(ListenerName::try_from("web-1").is_ok());
        assert!(ListenerName::try_from("a").is_ok());
        let sixty_three = "a".repeat(63);
        let parsed = ListenerName::try_from(sixty_three.as_str()).expect("63 bytes is legal");
        assert_eq!(parsed.as_str(), sixty_three);
    }

    #[test]
    fn listener_name_rejects_illegal_forms() {
        let sixty_four = "a".repeat(64);
        let cases: [&str; 7] = [
            "",
            sixty_four.as_str(),
            "Web",
            "web_1",
            "-web",
            "web-",
            "we b",
        ];
        for case in cases {
            match ListenerName::try_from(case) {
                Err(FieldError::ListenerName { found }) => assert_eq!(found, case),
                other => panic!("expected FieldError::ListenerName for {case:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn bind_addr_parses_v4_and_v6() {
        let v4 = BindAddr::try_from("0.0.0.0:8080").expect("valid IPv4 bind address");
        assert_eq!(v4.canonical_key(), "0.0.0.0:8080");
        let v6 = BindAddr::try_from("[::]:8080").expect("valid IPv6 bind address");
        assert_eq!(v6.canonical_key(), "[::]:8080");
    }

    #[test]
    fn bind_addr_rejects_partial_forms() {
        let cases: [&str; 5] = [":8080", "8080", "0.0.0.0", "[::]", ""];
        for case in cases {
            assert_eq!(
                BindAddr::try_from(case),
                Err(FieldError::BindAddr {
                    found: case.to_owned()
                }),
                "case: {case:?}"
            );
        }
    }

    #[test]
    fn bind_addr_canonical_key_is_stable() {
        let addr = BindAddr::try_from("127.0.0.1:80").expect("valid bind address");
        assert_eq!(addr.canonical_key(), "127.0.0.1:80");
        // A leading zero in an IPv4 octet is ambiguous between a decimal and an
        // octal reading and is a known SSRF and access-control bypass class;
        // Rust's Ipv4Addr parser rejects it, so the canonicaliser above never
        // sees two spellings of one IPv4 literal.
        assert_eq!(
            BindAddr::try_from("127.000.000.001:80"),
            Err(FieldError::BindAddr {
                found: "127.000.000.001:80".to_owned()
            })
        );
    }

    #[test]
    fn upstream_rejects_hostname_with_a_helpful_message() {
        let err = UpstreamAddr::try_from("example.com:80").expect_err("hostnames are rejected");
        assert!(matches!(err, FieldError::UpstreamAddr { ref found } if found == "example.com:80"));
        assert!(err.to_string().contains("hostnames"));
    }

    #[test]
    fn backlog_boundaries() {
        assert_eq!(
            Backlog::try_from(0u32),
            Err(FieldError::Backlog { found: 0 })
        );
        assert_eq!(Backlog::try_from(1u32).expect("1 is legal").get(), 1);
        assert_eq!(
            Backlog::try_from(65_535u32).expect("65535 is legal").get(),
            65_535
        );
        assert_eq!(
            Backlog::try_from(65_536u32),
            Err(FieldError::Backlog { found: 65_536 })
        );
    }

    #[test]
    fn millis_boundaries() {
        assert_eq!(Millis::try_from(0u32), Err(FieldError::Millis { found: 0 }));
        assert_eq!(Millis::try_from(1u32).expect("1 is legal").get(), 1);
        assert_eq!(
            Millis::try_from(86_400_000u32)
                .expect("86400000 is legal")
                .get(),
            86_400_000
        );
        assert_eq!(
            Millis::try_from(86_400_001u32),
            Err(FieldError::Millis { found: 86_400_001 })
        );
    }

    #[test]
    fn millis_as_duration() {
        assert_eq!(
            Millis::try_from(1_500u32)
                .expect("1500 is legal")
                .as_duration(),
            std::time::Duration::from_millis(1_500)
        );
    }

    // Closes BA1 and UA1: `socket_addr()` is the value the runtime binds and
    // dials, and no named test ever calls it.
    #[test]
    fn socket_addr_accessors_return_the_parsed_address() {
        assert_eq!(
            BindAddr::try_from("127.0.0.1:8080")
                .expect("legal")
                .socket_addr(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 8080))
        );
        assert_eq!(
            UpstreamAddr::try_from("10.0.0.5:9000")
                .expect("legal")
                .socket_addr(),
            std::net::SocketAddr::from(([10, 0, 0, 5], 9000))
        );
    }

    // Closes LN13, BA5, UA3, BK7, ML8: the author pinned FieldError's Display
    // exactly; the five newtypes' own Display impls were left uncovered by the
    // same argument.
    #[test]
    fn newtype_display_renders_the_value() {
        assert_eq!(
            ListenerName::try_from("web-1").expect("legal").to_string(),
            "web-1"
        );
        assert_eq!(
            BindAddr::try_from("[::]:8080").expect("legal").to_string(),
            "[::]:8080"
        );
        assert_eq!(
            UpstreamAddr::try_from("10.0.0.5:9000")
                .expect("legal")
                .to_string(),
            "10.0.0.5:9000"
        );
        assert_eq!(
            Backlog::try_from(4096u32).expect("legal").to_string(),
            "4096"
        );
        assert_eq!(
            Millis::try_from(1500u32).expect("legal").to_string(),
            "1500"
        );
    }

    // Closes ML5 and BK5: both are `pub` associated constants documented as the
    // legal floor and used as the total fallback in every serde default.
    #[test]
    fn min_constants_are_the_documented_floors() {
        assert_eq!(Millis::MIN.get(), 1);
        assert_eq!(Backlog::MIN.get(), 1);
    }

    // The canonicaliser is only ever asserted on inputs that are already in
    // canonical form, so nothing proves it collapses two spellings into one key,
    // which is the single reason the issue says it exists.
    #[test]
    fn canonical_key_collapses_equivalent_spellings() {
        let canonical = BindAddr::try_from("[::]:80")
            .expect("legal")
            .canonical_key();
        assert_eq!(
            BindAddr::try_from("[0:0:0:0:0:0:0:0]:80")
                .expect("legal")
                .canonical_key(),
            canonical
        );
        assert_eq!(
            BindAddr::try_from("[0000:0000:0000:0000:0000:0000:0000:0001]:80")
                .expect("legal")
                .canonical_key(),
            "[::1]:80"
        );
        assert_eq!(
            BindAddr::try_from("[::FFFF]:80")
                .expect("legal")
                .canonical_key(),
            "[::ffff]:80"
        );
        assert_eq!(
            BindAddr::try_from("0.0.0.0:00080")
                .expect("legal")
                .canonical_key(),
            BindAddr::try_from("0.0.0.0:80")
                .expect("legal")
                .canonical_key()
        );
    }

    #[test]
    fn mode_spelling_is_lowercase_only() {
        let ok: ModeSpec = serde_json::from_str("\"balanced\"").expect("lowercase parses");
        assert_eq!(ok, ModeSpec::Balanced);
        assert!(serde_json::from_str::<ModeSpec>("\"Balanced\"").is_err());
    }

    #[test]
    fn mode_spec_converts_to_runtime_mode() {
        assert_eq!(
            irontraffic_runtime::RuntimeMode::from(ModeSpec::Shard),
            irontraffic_runtime::RuntimeMode::Shard
        );
        assert_eq!(
            irontraffic_runtime::RuntimeMode::from(ModeSpec::Balanced),
            irontraffic_runtime::RuntimeMode::Balanced
        );
    }

    fn arb_ip() -> impl Strategy<Value = std::net::IpAddr> {
        prop_oneof![
            any::<[u8; 4]>().prop_map(|b| std::net::IpAddr::V4(std::net::Ipv4Addr::from(b))),
            any::<[u16; 8]>().prop_map(|b| std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn prop_newtype_round_trip(
            name in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
            backlog_val in 1u32..=65_535,
            millis_val in 1u32..=86_400_000,
            ip in arb_ip(),
            port in any::<u16>(),
        ) {
            let listener_name = ListenerName::try_from(name.as_str())
                .expect("the regex only generates legal listener names");
            let json = serde_json::to_string(&listener_name).expect("serializes");
            let restored: ListenerName = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(restored, listener_name);
            let via_owned = String::from(listener_name.clone());
            assert_eq!(
                ListenerName::try_from(via_owned).expect("the serialized form is always legal"),
                listener_name
            );

            let backlog = Backlog::try_from(backlog_val).expect("in range by construction");
            let json = serde_json::to_string(&backlog).expect("serializes");
            let restored: Backlog = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(restored, backlog);
            let via_u32: u32 = backlog.into();
            assert_eq!(Backlog::try_from(via_u32).expect("still in range"), backlog);

            let millis = Millis::try_from(millis_val).expect("in range by construction");
            let json = serde_json::to_string(&millis).expect("serializes");
            let restored: Millis = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(restored, millis);
            let via_u32: u32 = millis.into();
            assert_eq!(Millis::try_from(via_u32).expect("still in range"), millis);

            let socket_addr = std::net::SocketAddr::new(ip, port);
            let bind_addr = BindAddr::try_from(socket_addr.to_string().as_str())
                .expect("SocketAddr's own Display always round trips through BindAddr::try_from");
            let json = serde_json::to_string(&bind_addr).expect("serializes");
            let restored: BindAddr = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(restored, bind_addr);
            let via_string = String::from(bind_addr);
            assert_eq!(
                BindAddr::try_from(via_string.as_str()).expect("its own canonical form always parses"),
                bind_addr
            );
        }
    }
}
