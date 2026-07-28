// SPDX-License-Identifier: MIT OR Apache-2.0
//! The RFC 6455 HTTP/1.1 handshake.
//!
//! A connection becomes a tunnel only when BOTH directions validate. After a `101`
//! there is no HTTP framing left, so if the two endpoints did not actually agree that
//! the framing changed, one of them is parsing WebSocket frames as HTTP requests and an
//! attacker controls what it parses.
//!
//! `Upgrade` and `Connection` are hop-by-hop and are CONSUMED here. A downstream
//! `Upgrade: h2c` therefore cannot be forwarded, which is the Bishop Fox h2cSmuggler
//! remediation.
//!
//! Because they are hop-by-hop, neither field survives into a `CanonicalRequest`, so
//! both arrive as an [`UpgradeTokens`] value the caller filled from the wire section
//! BEFORE the strip. Looking for them in `req.headers` finds nothing, every time.
//!
//! **The four connection-disposal rules**, which this module cannot enforce itself
//! because it holds no socket, and which the caller MUST implement:
//!
//! 1. An upstream connection that answered `101` is NEVER returned to the pool,
//!    whether [`UpgradeResponse::verify`] succeeded or failed. A pooled post-`101`
//!    connection reads the next tenant's request line as a masked binary frame, which
//!    is upstream request smuggling with us as the vector.
//! 2. The same connection, once it becomes a tunnel, is owned by the tunnel until the
//!    tunnel ends and then closed. It is still never pooled.
//! 3. An unsolicited `101`, one answering a request that was not a validated upgrade at
//!    all, is not forwarded and its connection is closed. RFC 9110 permits `101` only in
//!    response to an `Upgrade` request, so an unsolicited one means we and the upstream
//!    disagree about which request it just answered, which is the desync condition
//!    itself.
//! 4. The DOWNSTREAM connection is different: we never sent it a `101`, so a failed
//!    upgrade (answered `400`, `426` or `502`) leaves its HTTP framing intact and it
//!    remains reusable. Closing it on every failed upgrade would be needless churn.
//!
//! Validating the response (rules above the fold) protects US. Disposing of the
//! connections correctly (this list) protects the OTHER tenants of the upstream pool.
//! `UpgradeRequest::parse` and `UpgradeResponse::verify` hold no socket and cannot
//! enforce any of this; what this module delivers is the rule, stated here and in
//! `docs/THREAT-MODEL.md`. **Nothing in this corpus yet wires a connection handler to
//! call these functions**; see the module's own issue for the follow-up this gap is
//! tracked against.

use base64ct::{Base64, Encoding};
use irontraffic_http::canonical::CanonicalRequest;
use irontraffic_http::field::trim_ows;
use irontraffic_http::framing::RequestFraming;
use irontraffic_http::scalar::Method;
use irontraffic_http::section::{DuplicateField, FieldSection};
use irontraffic_http::{RejectReason, framing};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;

/// The RFC 6455 Section 1.3 GUID, appended to the key before hashing.
pub const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Decoded `Sec-WebSocket-Key` length, in bytes.
pub const KEY_BYTES: usize = 16;

/// Base64 `Sec-WebSocket-Key` length, in characters.
pub const KEY_B64_LEN: usize = 24;

/// Base64 `Sec-WebSocket-Accept` length, in characters.
pub const ACCEPT_B64_LEN: usize = 28;

/// The only supported version.
pub const WS_VERSION: u32 = 13;

/// Subprotocols recorded from a request. Extras are a rejection, not a truncation,
/// because a subprotocol list is chosen by the client and 8 is generous.
pub const MAX_SUBPROTOCOLS: usize = 8;

/// Total bytes of subprotocol names one request may offer. Eight names averaging 32
/// bytes is generous for a token list; more is `SubprotocolListTooLong`, for the same
/// reason a count above [`MAX_SUBPROTOCOLS`] is a rejection rather than a truncation.
pub const MAX_SUBPROTOCOL_BYTES: usize = 256;

// The five field names this module reads out of a section. They are spelled as byte
// literals because none of them is a `KnownHeader`: `irontraffic-http` enumerates only
// the fields it has rules for, and these have none outside this crate. Names in a
// canonical section are already lowercased, so no case folding is needed on lookup.
const SEC_WEBSOCKET_KEY: &[u8] = b"sec-websocket-key";
const SEC_WEBSOCKET_VERSION: &[u8] = b"sec-websocket-version";
const SEC_WEBSOCKET_PROTOCOL: &[u8] = b"sec-websocket-protocol";
const SEC_WEBSOCKET_EXTENSIONS: &[u8] = b"sec-websocket-extensions";
const SEC_WEBSOCKET_ACCEPT: &[u8] = b"sec-websocket-accept";

// There is deliberately no `UPGRADE` or `CONNECTION` constant in this module: neither
// field is readable from a section this module is ever handed, and a constant for one
// would invite the lookup that silently returns `None`. Both arrive through
// [`UpgradeTokens`].

/// The `Upgrade` and `Connection` evidence, read from a field section BEFORE the
/// hop-by-hop strip removes it.
///
/// Both fields are hop-by-hop. `strip_ingress` removes them and
/// `CanonicalRequestBuilder::build` refuses to build a request that still carries one,
/// so reading them out of a `CanonicalRequest` yields `None` every time and every real
/// upgrade is silently missed. The caller reads them from the wire section first, the
/// same way `hop-by-hop-strip-set`'s own doc comment says the forwarding-chain code
/// reads the identity fields before the strip and re-synthesises what it needs
/// afterwards.
///
/// `ws-extended-connect-bridge` (#204) names [`MAX_SUBPROTOCOL_BYTES`] and
/// [`KEY_B64_LEN`], so both are public rather than crate-private.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpgradeTokens<'a> {
    /// The single `Upgrade` field value, OWS intact, or `None` when the field was
    /// absent.
    pub upgrade: Option<&'a [u8]>,
    /// True when any `Connection` field line contained the `upgrade` token. The caller
    /// computes it with [`irontraffic_http::strip::connection_has_token`], which this
    /// issue exports so there is exactly one tokenizer.
    pub connection_has_upgrade: bool,
    /// True when more than one `Upgrade` field line was present, which the caller
    /// observes as `get_unique_known(KnownHeader::Upgrade)` returning `DuplicateField`
    /// and which this module turns into a 400 rather than choosing one of them.
    pub duplicate_upgrade: bool,
}

/// A validated RFC 6455 upgrade request.
///
/// Constructing one is the ONLY way to conclude that a request is a WebSocket
/// upgrade. There is no boolean `is_websocket` anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRequest {
    /// The 16 decoded key bytes.
    key: [u8; KEY_BYTES],
    /// The key exactly as it appeared on the wire, for forwarding unchanged.
    key_b64: [u8; KEY_B64_LEN],
    /// The offered subprotocol names, COPIED into a fixed inline buffer, plus the
    /// ranges into it and how many are valid. They are copied rather than kept as
    /// ranges into the request head because `UpgradeRequest` outlives the head: it is
    /// held from the moment the request is parsed until the upstream `101` is
    /// verified, and a range into a buffer that has been recycled resolves to another
    /// request's bytes. Copying keeps the type `'static`, `Clone` and allocation-free.
    subprotocol_bytes: [u8; MAX_SUBPROTOCOL_BYTES],
    subprotocol_ranges: [(u16, u16); MAX_SUBPROTOCOLS],
    subprotocol_len: u8,
    /// True when the client offered any extension. We negotiate none, so this exists
    /// only so the response check can refuse an extension nobody could have accepted.
    ///
    /// Unread within this issue: `verify`'s own extension check (step 4) is
    /// unconditional (we offer the upstream no extensions regardless of what the
    /// downstream client offered, so any extension in a `101` is unrequested either
    /// way), matching `ws-extended-connect-bridge` (#204)'s not-yet-landed use of the
    /// same bookkeeping. There is deliberately no public accessor for it, matching the
    /// issue's own `Public API` listing for `UpgradeRequest`, which names none; the
    /// same precedent as `irontraffic_http::h1::parser::RawHead::target` (kept
    /// `pub(crate)` with no reader yet, so the invariant it stores for is true from
    /// the moment this type exists rather than only once a later issue lands).
    #[allow(
        dead_code,
        reason = "stored per the issue's own struct definition, read only by a future \
                  ws-extended-connect-bridge (#204) consumer that has not landed yet; see \
                  the field's own doc comment"
    )]
    offered_extensions: bool,
}

/// A validated `101` response.
///
/// `selected_subprotocol` is a RANGE into the response head's own [`FieldSection`]
/// arena (the same reference frame `FieldSlot`'s own doc comment describes: offsets
/// relative to the start of that arena, not to any read buffer), so this value must
/// not outlive that `FieldSection`. That is the opposite discipline from
/// `UpgradeRequest`, which COPIES its subprotocol names because it is held from
/// request parse until the upstream's `101` arrives; an `UpgradeResponse` is consumed
/// by the caller in the same turn the response was read. The asymmetry is deliberate
/// and it is stated because a range that outlives its buffer resolves to another
/// request's bytes, which would mean forwarding a subprotocol name we never saw. A
/// caller that needs to hold one across a turn copies first; it does not extend the
/// lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeResponse {
    /// The subprotocol the upstream selected, as a range into the response head.
    pub selected_subprotocol: Option<(u16, u16)>,
}

/// A WebSocket handshake could not be completed.
#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// `Upgrade` was present but was not exactly `websocket`.
    UpgradeTokenNotWebsocket,
    /// `Connection` did not contain the `upgrade` token.
    ConnectionTokenMissing,
    /// The method was not `GET`.
    MethodNotGet {
        /// What arrived.
        method: Method,
    },
    /// The upgrade request declared a body.
    UpgradeWithBody,
    /// `Sec-WebSocket-Version` was absent.
    VersionMissing,
    /// A version other than 13.
    UnsupportedVersion {
        /// What arrived.
        found: u32,
    },
    /// `Sec-WebSocket-Key` was absent.
    KeyMissing,
    /// The key was not [`KEY_B64_LEN`] characters.
    KeyWrongLength {
        /// The observed length.
        len: usize,
    },
    /// The key was not valid base64 of 16 bytes.
    KeyNotBase64,
    /// More than [`MAX_SUBPROTOCOLS`] were offered.
    TooManySubprotocols,
    /// The offered subprotocol names exceed [`MAX_SUBPROTOCOL_BYTES`] in total.
    SubprotocolListTooLong {
        /// The observed total.
        len: usize,
    },
    /// The upstream did not answer `101`.
    NotSwitchingProtocols {
        /// The status.
        status: u16,
    },
    /// The `101` carried no `Sec-WebSocket-Accept`.
    AcceptMissing,
    /// The accept value did not match the key we sent.
    AcceptMismatch,
    /// The upstream negotiated an extension nobody offered.
    UnrequestedExtension,
    /// The upstream selected a subprotocol the client did not offer.
    UnofferedSubprotocol,
    /// More than one `Upgrade` field line was present, which
    /// [`UpgradeTokens::duplicate_upgrade`] reports. A rejection rather than a choice:
    /// two values one of which we honour is the same shape every framing rule in the
    /// product refuses.
    DuplicateUpgrade,
    /// A field this module reads with `get_unique` appeared more than once.
    ///
    /// NOT `#[from]`: [`irontraffic_http::section::DuplicateField`] deliberately carries
    /// no `Display` or `std::error::Error` impl, matching `RejectReason`'s own D3 rule
    /// in `irontraffic-http/src/error.rs` ("a `Display` impl would put it in reach of
    /// `format!("{err}")` in a responder"). `thiserror`'s `#[from]` needs the source
    /// type to implement `std::error::Error` to generate `source()`, so that attribute
    /// cannot be used here; the plain [`From`] impl below this enum gives every `?` on
    /// a `get_unique` call the same one-line conversion without it.
    Duplicate(DuplicateField),
    /// A field-level rejection from the shared validation. Same reasoning as
    /// `Duplicate` above: [`irontraffic_http::RejectReason`] implements neither
    /// `Display` nor `std::error::Error` by design, so this is a hand-written [`From`]
    /// rather than `#[from]`; `parse_ws_version` and the field helpers report a
    /// `RejectReason` and this module propagates them with `?`.
    Field(RejectReason),
}

impl core::fmt::Display for HandshakeError {
    // NOT `#[derive(thiserror::Error)]`: two of this enum's variants wrap a type that
    // deliberately implements neither `Display` nor `std::error::Error` (see the
    // `Duplicate` and `Field` variants' own doc comments), and `thiserror`'s `#[from]`
    // / `#[source]` attributes require that bound to generate `Error::source()`.
    // Writing the `Display` impl by hand, with no field access on `Duplicate` or
    // `Field` beyond `Debug`, keeps this compiling without leaning on either bound.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HandshakeError::UpgradeTokenNotWebsocket => {
                write!(f, "upgrade token is not websocket")
            }
            HandshakeError::ConnectionTokenMissing => {
                write!(f, "connection header does not contain the upgrade token")
            }
            HandshakeError::MethodNotGet { method } => {
                write!(f, "websocket upgrade method is {method:?}, expected GET")
            }
            HandshakeError::UpgradeWithBody => write!(f, "websocket upgrade carries a body"),
            HandshakeError::VersionMissing => write!(f, "sec-websocket-version is missing"),
            HandshakeError::UnsupportedVersion { found } => write!(
                f,
                "sec-websocket-version is {found}, only {WS_VERSION} is supported"
            ),
            HandshakeError::KeyMissing => write!(f, "sec-websocket-key is missing"),
            HandshakeError::KeyWrongLength { len } => write!(
                f,
                "sec-websocket-key is {len} characters, expected {KEY_B64_LEN}"
            ),
            HandshakeError::KeyNotBase64 => {
                write!(f, "sec-websocket-key is not base64 of 16 bytes")
            }
            HandshakeError::TooManySubprotocols => {
                write!(f, "more than {MAX_SUBPROTOCOLS} subprotocols offered")
            }
            HandshakeError::SubprotocolListTooLong { len } => write!(
                f,
                "subprotocol list is {len} bytes, above {MAX_SUBPROTOCOL_BYTES}"
            ),
            HandshakeError::NotSwitchingProtocols { status } => {
                write!(f, "upstream answered {status}, expected 101")
            }
            HandshakeError::AcceptMissing => {
                write!(f, "sec-websocket-accept is missing from the 101")
            }
            HandshakeError::AcceptMismatch => {
                write!(f, "sec-websocket-accept does not match the key")
            }
            HandshakeError::UnrequestedExtension => {
                write!(f, "upstream negotiated an extension that was not offered")
            }
            HandshakeError::UnofferedSubprotocol => {
                write!(f, "upstream selected a subprotocol that was not offered")
            }
            HandshakeError::DuplicateUpgrade => write!(f, "more than one upgrade field line"),
            HandshakeError::Duplicate(_) => write!(f, "field appeared more than once"),
            HandshakeError::Field(reason) => write!(f, "field rejected: {reason:?}"),
        }
    }
}

impl core::error::Error for HandshakeError {}

impl From<DuplicateField> for HandshakeError {
    fn from(value: DuplicateField) -> Self {
        HandshakeError::Duplicate(value)
    }
}

impl From<RejectReason> for HandshakeError {
    fn from(value: RejectReason) -> Self {
        HandshakeError::Field(value)
    }
}

/// Which side of the handshake produced an error.
///
/// The same variant can arise on both sides: an `Upgrade` value that is not `websocket`
/// is a client fault on the request and a gateway fault on a `101`. The status the
/// DOWNSTREAM client is answered with therefore depends on the side, and a `status()`
/// that took no argument could not be right for both. `verify` failures are always
/// [`HandshakeSide::Response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeSide {
    /// The downstream request failed validation.
    Request,
    /// The upstream `101` failed validation.
    Response,
}

impl HandshakeError {
    /// The status to answer the DOWNSTREAM client with.
    ///
    /// [`HandshakeSide::Response`] is always 502: the client's request may have been
    /// perfect and the upstream is what misbehaved. On [`HandshakeSide::Request`] it is
    /// 426 for [`HandshakeError::UnsupportedVersion`], which is the one failure a client
    /// can act on, and 400 for everything else.
    #[must_use]
    pub const fn status(&self, side: HandshakeSide) -> u16 {
        match side {
            HandshakeSide::Response => 502,
            HandshakeSide::Request => match self {
                HandshakeError::UnsupportedVersion { .. } => 426,
                _ => 400,
            },
        }
    }

    /// The stable, `snake_case` metric label.
    #[must_use]
    pub const fn metric_label(&self) -> &'static str {
        match self {
            HandshakeError::UpgradeTokenNotWebsocket => "ws_upgrade_token_not_websocket",
            HandshakeError::ConnectionTokenMissing => "ws_connection_token_missing",
            HandshakeError::MethodNotGet { .. } => "ws_method_not_get",
            HandshakeError::UpgradeWithBody => "ws_upgrade_with_body",
            HandshakeError::VersionMissing => "ws_version_missing",
            HandshakeError::UnsupportedVersion { .. } => "ws_unsupported_version",
            HandshakeError::KeyMissing => "ws_key_missing",
            HandshakeError::KeyWrongLength { .. } => "ws_key_wrong_length",
            HandshakeError::KeyNotBase64 => "ws_key_not_base64",
            HandshakeError::TooManySubprotocols => "ws_too_many_subprotocols",
            HandshakeError::SubprotocolListTooLong { .. } => "ws_subprotocol_list_too_long",
            HandshakeError::NotSwitchingProtocols { .. } => "ws_not_switching_protocols",
            HandshakeError::AcceptMissing => "ws_accept_missing",
            HandshakeError::AcceptMismatch => "ws_accept_mismatch",
            HandshakeError::UnrequestedExtension => "ws_unrequested_extension",
            HandshakeError::UnofferedSubprotocol => "ws_unoffered_subprotocol",
            HandshakeError::DuplicateUpgrade => "ws_duplicate_upgrade",
            HandshakeError::Duplicate(_) => "ws_duplicate_field",
            HandshakeError::Field(reason) => reason.metric_label(),
        }
    }
}

/// Decodes `key_b64` (already length-checked as [`KEY_B64_LEN`] characters) into
/// exactly [`KEY_BYTES`] bytes, or `None` when it is not valid base64 of that length.
fn base64_decode_key(key_b64: [u8; KEY_B64_LEN]) -> Option<[u8; KEY_BYTES]> {
    let mut buf = [0_u8; KEY_BYTES];
    let decoded_len = match Base64::decode(key_b64, &mut buf) {
        Ok(decoded) => decoded.len(),
        Err(_) => return None,
    };
    if decoded_len == KEY_BYTES {
        Some(buf)
    } else {
        None
    }
}

/// Parses the numeric `Sec-WebSocket-Version` value.
///
/// `Sec-WebSocket-Version` is a bare, non-negative decimal integer with the exact same
/// grammar (`1*DIGIT`, no sign, no leading `+`) as `Content-Length`, so this reuses
/// [`irontraffic_http::framing::parse_content_length`] rather than inventing a second
/// digit parser: this crate's dependency already establishes "one parse policy per
/// grammar, reused, not re-derived" for exactly this reason (see `is_tchar`'s own doc
/// comment in `irontraffic-http`). A value that overflows `u32` but still fits the
/// `u64` the shared parser accepts is clamped to `u32::MAX`, which is never
/// [`WS_VERSION`] and so always resolves to [`HandshakeError::UnsupportedVersion`].
fn parse_ws_version(value: &[u8]) -> Result<u32, RejectReason> {
    let parsed = framing::parse_content_length(value)?;
    Ok(u32::try_from(parsed).unwrap_or(u32::MAX))
}

/// Finds the `(start, end)` byte range the `sec-websocket-protocol` field occupies
/// inside `headers`'s own arena, by scanning [`FieldSection::slots`] for the slot
/// [`FieldSection::get_unique`] resolved it from. `FieldSlot`'s offsets are already
/// relative to the arena's own start (its own doc comment in `irontraffic-http`
/// states this), which is exactly the reference frame [`UpgradeResponse::selected_subprotocol`]
/// promises: a range the CALLER can later resolve back through the same
/// [`FieldSection`].
///
/// Only ever called after `headers.get_unique(SEC_WEBSOCKET_PROTOCOL)` has already
/// returned `Ok(Some(_))`, which proves exactly one such slot exists; the loop below
/// therefore always finds it; the panic-free fallback exists only because this
/// function's return type has no way to express "impossible".
fn subprotocol_value_range(headers: &FieldSection) -> (u16, u16) {
    for (i, slot) in headers.slots().iter().enumerate() {
        if headers.name_at(i) == Some(SEC_WEBSOCKET_PROTOCOL) {
            let start = u16::try_from(slot.value_off).unwrap_or(u16::MAX);
            let value_end = u64::from(slot.value_off).saturating_add(u64::from(slot.value_len));
            let end = u16::try_from(value_end).unwrap_or(u16::MAX);
            return (start, end);
        }
    }
    debug_assert!(
        false,
        "sec-websocket-protocol slot vanished between get_unique and this scan"
    );
    (0, 0)
}

impl UpgradeRequest {
    /// Validates `req` as an RFC 6455 upgrade.
    ///
    /// `tokens` carries the `Upgrade` and `Connection` evidence, which `req` provably
    /// does not: both are hop-by-hop and the strip removed them before `req` was built.
    ///
    /// Returns `Ok(None)` when the request is not an upgrade at all, which is the
    /// common case and is not an error.
    ///
    /// # Errors
    /// [`HandshakeError`], each variant carrying the status the caller must answer
    /// with. Every failure closes the connection: an upgrade we refused leaves a client
    /// that may already be framing WebSocket.
    #[allow(
        clippy::missing_errors_doc,
        reason = "documented above the fn signature rather than restated by the lint's exact \
                  expected shape; every variant of HandshakeError is named there"
    )]
    pub fn parse(
        req: &CanonicalRequest,
        tokens: UpgradeTokens<'_>,
    ) -> Result<Option<UpgradeRequest>, HandshakeError> {
        // Step 0.
        if tokens.duplicate_upgrade {
            return Err(HandshakeError::DuplicateUpgrade);
        }

        // Step 1: not an upgrade at all.
        let Some(upgrade) = tokens.upgrade else {
            return Ok(None);
        };

        // Step 2: exactly one value, `websocket`, ASCII case-insensitive. Step 0
        // already refused a duplicate `Upgrade` line; a comma inside this single
        // value is caught here because "websocket, h2c" is not equal to "websocket".
        if !trim_ows(upgrade).eq_ignore_ascii_case(b"websocket") {
            return Err(HandshakeError::UpgradeTokenNotWebsocket);
        }

        // Step 3.
        if !tokens.connection_has_upgrade {
            return Err(HandshakeError::ConnectionTokenMissing);
        }

        // Step 4.
        if req.method != Method::Get {
            return Err(HandshakeError::MethodNotGet { method: req.method });
        }

        // Step 5.
        if req.framing != RequestFraming::Empty {
            return Err(HandshakeError::UpgradeWithBody);
        }

        // Step 6: version.
        let Some(ver) = req.headers.get_unique(SEC_WEBSOCKET_VERSION)? else {
            return Err(HandshakeError::VersionMissing);
        };
        let found = parse_ws_version(ver)?;
        if found != WS_VERSION {
            return Err(HandshakeError::UnsupportedVersion { found });
        }

        // Step 7: key.
        let Some(key_b64_slice) = req.headers.get_unique(SEC_WEBSOCKET_KEY)? else {
            return Err(HandshakeError::KeyMissing);
        };
        if key_b64_slice.len() != KEY_B64_LEN {
            return Err(HandshakeError::KeyWrongLength {
                len: key_b64_slice.len(),
            });
        }
        let mut key_b64 = [0_u8; KEY_B64_LEN];
        // The length check just above proved `key_b64_slice.len() == KEY_B64_LEN`, so
        // this copy always fits.
        key_b64.copy_from_slice(key_b64_slice);
        let key = base64_decode_key(key_b64).ok_or(HandshakeError::KeyNotBase64)?;

        // Step 8: subprotocols, a `#list` across every field line, in order, copied
        // into the inline buffer.
        let mut subprotocol_bytes = [0_u8; MAX_SUBPROTOCOL_BYTES];
        let mut subprotocol_ranges = [(0_u16, 0_u16); MAX_SUBPROTOCOLS];
        let mut subprotocol_len = 0_u8;
        let mut cursor = 0_usize;
        for value in req.headers.get_all(SEC_WEBSOCKET_PROTOCOL) {
            for raw in value.split(|&b| b == b',') {
                let name = trim_ows(raw);
                // An empty list element names no subprotocol, the same rule
                // `irontraffic_http::strip::collect_connection_tokens` applies to
                // `Connection` tokens (RFC 9110 Section 5.6.1: empty `#list` elements
                // do not contribute to the count of elements present).
                if name.is_empty() {
                    continue;
                }
                if usize::from(subprotocol_len) >= MAX_SUBPROTOCOLS {
                    return Err(HandshakeError::TooManySubprotocols);
                }
                let Some(end) = cursor.checked_add(name.len()) else {
                    return Err(HandshakeError::SubprotocolListTooLong { len: usize::MAX });
                };
                if end > MAX_SUBPROTOCOL_BYTES {
                    return Err(HandshakeError::SubprotocolListTooLong { len: end });
                }
                let Some(dst) = subprotocol_bytes.get_mut(cursor..end) else {
                    return Err(HandshakeError::SubprotocolListTooLong { len: end });
                };
                dst.copy_from_slice(name);
                let start_u16 = u16::try_from(cursor).unwrap_or(u16::MAX);
                let end_u16 = u16::try_from(end).unwrap_or(u16::MAX);
                if let Some(slot) = subprotocol_ranges.get_mut(usize::from(subprotocol_len)) {
                    *slot = (start_u16, end_u16);
                }
                subprotocol_len = subprotocol_len.saturating_add(1);
                cursor = end;
            }
        }

        // Step 9.
        let offered_extensions = req
            .headers
            .get_all(SEC_WEBSOCKET_EXTENSIONS)
            .next()
            .is_some();

        // Step 10.
        Ok(Some(UpgradeRequest {
            key,
            key_b64,
            subprotocol_bytes,
            subprotocol_ranges,
            subprotocol_len,
            offered_extensions,
        }))
    }

    /// The key exactly as it appeared, for forwarding unchanged to an HTTP/1 upstream.
    #[must_use]
    pub const fn key_b64(&self) -> &[u8; KEY_B64_LEN] {
        &self.key_b64
    }

    /// The 16 decoded key bytes.
    #[must_use]
    pub const fn key(&self) -> &[u8; KEY_BYTES] {
        &self.key
    }

    /// Subprotocols the client offered, in order.
    pub fn subprotocols(&self) -> impl Iterator<Item = &[u8]> {
        self.subprotocol_ranges
            .iter()
            .take(usize::from(self.subprotocol_len))
            .filter_map(move |&(start, end)| {
                self.subprotocol_bytes
                    .get(usize::from(start)..usize::from(end))
            })
    }

    /// True when `name` is one of the offered subprotocols.
    #[must_use]
    pub fn offered(&self, name: &[u8]) -> bool {
        self.subprotocols().any(|s| s == name)
    }

    /// Builds the request value for a handshake WE synthesised: `nonce` is the 16 key
    /// bytes we drew ourselves, and the three subprotocol arguments are copied verbatim
    /// out of an `extended::ExtendedConnect`, whose buffers are declared with these same
    /// two constants, so the copy is size-checked by the compiler and this constructor
    /// cannot fail. It base64-encodes `nonce` into `key_b64` itself.
    ///
    /// **`pub(crate)`, never `pub`.** Outside this crate the only way to obtain an
    /// `UpgradeRequest` is still `parse`, which is what invariant 1 of the module's own
    /// issue says. The one in-crate exception exists because [`UpgradeResponse::verify`]
    /// takes an `&UpgradeRequest` and `ws-extended-connect-bridge` (#204) has no wire
    /// request to parse: on HTTP/2 and HTTP/3 the client sends no key at all, so the
    /// bridge generates one, sends it, and must verify the accept value against it.
    #[allow(
        dead_code,
        reason = "the only caller is ws-extended-connect-bridge (#204), which has not landed \
                  yet; this module's own tests and the fuzz target keep parse/verify compiled \
                  and linted, but nothing in this issue calls synthetic, per the issue's own \
                  'do NOT invent that listener wiring here' instruction. Kept pub(crate) now so \
                  invariant 1 (constructible only through parse, outside this crate) is true \
                  from the moment this type exists rather than only once #204 lands, matching \
                  the precedent already in irontraffic_http::h1::parser::RawHead::target"
    )]
    pub(crate) fn synthetic(
        nonce: [u8; KEY_BYTES],
        subprotocol_bytes: [u8; MAX_SUBPROTOCOL_BYTES],
        subprotocol_ranges: [(u16, u16); MAX_SUBPROTOCOLS],
        subprotocol_len: u8,
    ) -> Self {
        let mut key_b64 = [0_u8; KEY_B64_LEN];
        let encoded = Base64::encode(&nonce, &mut key_b64);
        debug_assert!(
            encoded.is_ok(),
            "encoding a fixed 16-byte nonce into a fixed 24-byte buffer cannot fail"
        );
        UpgradeRequest {
            key: nonce,
            key_b64,
            subprotocol_bytes,
            subprotocol_ranges,
            subprotocol_len,
            offered_extensions: false,
        }
    }
}

/// Computes `Sec-WebSocket-Accept` from a key.
///
/// Hashes the base64 STRING as it appeared on the wire concatenated with [`WS_GUID`],
/// per RFC 6455 Section 4.2.2. Hashing the DECODED bytes instead produces a
/// plausible-looking value that no real client accepts, and the bug survives any test
/// that uses the same implementation on both sides.
#[must_use]
pub fn accept_key(key_b64: &[u8; KEY_B64_LEN]) -> [u8; ACCEPT_B64_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(key_b64); // the ASCII base64 form, NOT the decoded bytes
    hasher.update(WS_GUID);
    let digest = hasher.finalize(); // 20 bytes

    let mut out = [0_u8; ACCEPT_B64_LEN];
    let encoded = Base64::encode(&digest[..], &mut out);
    debug_assert!(
        encoded.is_ok(),
        "encoding a fixed 20-byte SHA-1 digest into a fixed 28-byte buffer cannot fail"
    );
    out
}

impl UpgradeResponse {
    /// Validates an upstream response against the request we sent.
    ///
    /// `headers` MUST be the response section as it arrived, before `strip_response`,
    /// and `tokens` MUST be filled from that same section: `Upgrade` and `Connection`
    /// are hop-by-hop on a response too.
    ///
    /// # Errors
    /// [`HandshakeError`]. On any error the upstream connection is POISONED and closed,
    /// never returned to the pool: an upstream that answered a WebSocket upgrade
    /// incorrectly is an upstream whose framing state we do not know.
    #[allow(
        clippy::missing_errors_doc,
        reason = "documented above the fn signature; every variant of HandshakeError is \
                  named there"
    )]
    pub fn verify(
        req: &UpgradeRequest,
        status: u16,
        headers: &FieldSection,
        tokens: UpgradeTokens<'_>,
    ) -> Result<UpgradeResponse, HandshakeError> {
        // Step 1.
        if status != 101 {
            return Err(HandshakeError::NotSwitchingProtocols { status });
        }

        // Step 2: the response half of the same `Upgrade`/`Connection` hazard the
        // request half has.
        if tokens.duplicate_upgrade {
            return Err(HandshakeError::DuplicateUpgrade);
        }
        let Some(upgrade) = tokens.upgrade else {
            return Err(HandshakeError::UpgradeTokenNotWebsocket);
        };
        if !trim_ows(upgrade).eq_ignore_ascii_case(b"websocket") {
            return Err(HandshakeError::UpgradeTokenNotWebsocket);
        }
        if !tokens.connection_has_upgrade {
            return Err(HandshakeError::ConnectionTokenMissing);
        }

        // Step 3: the accept value, recomputed from the key we forwarded and compared
        // in constant time.
        let Some(accept) = headers.get_unique(SEC_WEBSOCKET_ACCEPT)? else {
            return Err(HandshakeError::AcceptMissing);
        };
        let expected = accept_key(&req.key_b64);
        // A length mismatch is reported before the comparison runs: `ct_eq` on
        // unequal-length slices short-circuits on the length check (subtle's own doc
        // says so), so it is not constant time for that case, and there is no secret
        // to protect in the length itself.
        if accept.len() != ACCEPT_B64_LEN {
            return Err(HandshakeError::AcceptMismatch);
        }
        if !bool::from(accept.ct_eq(&expected[..])) {
            return Err(HandshakeError::AcceptMismatch);
        }

        // Step 4: we requested no extensions, so any is unrequested.
        if headers.get_all(SEC_WEBSOCKET_EXTENSIONS).next().is_some() {
            return Err(HandshakeError::UnrequestedExtension);
        }

        // Step 5: subprotocol.
        match headers.get_unique(SEC_WEBSOCKET_PROTOCOL)? {
            None => Ok(UpgradeResponse {
                selected_subprotocol: None,
            }),
            Some(p) if req.offered(p) => Ok(UpgradeResponse {
                selected_subprotocol: Some(subprotocol_value_range(headers)),
            }),
            Some(_) => Err(HandshakeError::UnofferedSubprotocol),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6455_accept_vector_const_adjacent() {
        // The RFC 6455 Section 1.3 test vector, asserted here as a const-adjacent
        // check in addition to `tests/handshake.rs`'s own `rfc_6455_accept_vector`:
        // this is the exact computation `accept_key` performs, pinned at the
        // narrowest possible scope.
        let key_b64 = *b"dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(&accept_key(&key_b64), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    /// One concrete value per `HandshakeError` variant, with its expected metric
    /// label and its expected status on each `HandshakeSide`. Neither
    /// `HandshakeError::metric_label` nor its `Display` impl is exercised by any
    /// test named in the module's own issue, which is exactly the gap a
    /// `replace metric_label -> "" ` or `replace fmt -> Ok(Default::default())`
    /// mutation exploits; this closes it, mirroring
    /// `irontraffic_http::error::RejectReason`'s own `full_status_table` /
    /// `metric_labels_are_unique` / `metric_labels_are_snake_case` convention.
    ///
    /// Exhaustive match, no wildcard arm: adding a variant to `HandshakeError`
    /// without adding a case to `handshake_error_mappings_are_exhaustive_and_pinned`'s
    /// own `cases` array is still something the compiler permits, since the array
    /// length is not tied to the enum by the type system; this ordinal function is
    /// what actually enforces completeness, the same way `RejectReason::tests::seen`
    /// does for its own enum.
    fn handshake_error_ordinal(e: &HandshakeError) -> usize {
        match e {
            HandshakeError::UpgradeTokenNotWebsocket => 0,
            HandshakeError::ConnectionTokenMissing => 1,
            HandshakeError::MethodNotGet { .. } => 2,
            HandshakeError::UpgradeWithBody => 3,
            HandshakeError::VersionMissing => 4,
            HandshakeError::UnsupportedVersion { .. } => 5,
            HandshakeError::KeyMissing => 6,
            HandshakeError::KeyWrongLength { .. } => 7,
            HandshakeError::KeyNotBase64 => 8,
            HandshakeError::TooManySubprotocols => 9,
            HandshakeError::SubprotocolListTooLong { .. } => 10,
            HandshakeError::NotSwitchingProtocols { .. } => 11,
            HandshakeError::AcceptMissing => 12,
            HandshakeError::AcceptMismatch => 13,
            HandshakeError::UnrequestedExtension => 14,
            HandshakeError::UnofferedSubprotocol => 15,
            HandshakeError::DuplicateUpgrade => 16,
            HandshakeError::Duplicate(_) => 17,
            HandshakeError::Field(_) => 18,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table of 19 HandshakeError variants, each with its expected metric \
                  label and status; splitting it would break the 1:1 mapping to the enum \
                  the ordinal function above enforces"
    )]
    #[test]
    fn handshake_error_mappings_are_exhaustive_and_pinned() {
        let cases: [(HandshakeError, &str, u16); 19] = [
            (
                HandshakeError::UpgradeTokenNotWebsocket,
                "ws_upgrade_token_not_websocket",
                400,
            ),
            (
                HandshakeError::ConnectionTokenMissing,
                "ws_connection_token_missing",
                400,
            ),
            (
                HandshakeError::MethodNotGet {
                    method: Method::Post,
                },
                "ws_method_not_get",
                400,
            ),
            (HandshakeError::UpgradeWithBody, "ws_upgrade_with_body", 400),
            (HandshakeError::VersionMissing, "ws_version_missing", 400),
            (
                HandshakeError::UnsupportedVersion { found: 8 },
                "ws_unsupported_version",
                426,
            ),
            (HandshakeError::KeyMissing, "ws_key_missing", 400),
            (
                HandshakeError::KeyWrongLength { len: 23 },
                "ws_key_wrong_length",
                400,
            ),
            (HandshakeError::KeyNotBase64, "ws_key_not_base64", 400),
            (
                HandshakeError::TooManySubprotocols,
                "ws_too_many_subprotocols",
                400,
            ),
            (
                HandshakeError::SubprotocolListTooLong { len: 257 },
                "ws_subprotocol_list_too_long",
                400,
            ),
            (
                HandshakeError::NotSwitchingProtocols { status: 200 },
                "ws_not_switching_protocols",
                400,
            ),
            (HandshakeError::AcceptMissing, "ws_accept_missing", 400),
            (HandshakeError::AcceptMismatch, "ws_accept_mismatch", 400),
            (
                HandshakeError::UnrequestedExtension,
                "ws_unrequested_extension",
                400,
            ),
            (
                HandshakeError::UnofferedSubprotocol,
                "ws_unoffered_subprotocol",
                400,
            ),
            (
                HandshakeError::DuplicateUpgrade,
                "ws_duplicate_upgrade",
                400,
            ),
            (
                HandshakeError::Duplicate(DuplicateField { name_len: 6 }),
                "ws_duplicate_field",
                400,
            ),
            (
                HandshakeError::Field(RejectReason::FieldNameEmpty),
                RejectReason::FieldNameEmpty.metric_label(),
                400,
            ),
        ];

        let mut labels: Vec<&str> = Vec::with_capacity(cases.len());
        for (i, (err, label, req_status)) in cases.iter().enumerate() {
            assert_eq!(
                handshake_error_ordinal(err),
                i,
                "case {i} ({err:?}) is out of order or a variant is missing from `cases`"
            );
            assert_eq!(err.metric_label(), *label, "{err:?} metric label");
            assert_eq!(
                err.status(HandshakeSide::Request),
                *req_status,
                "{err:?} status on HandshakeSide::Request"
            );
            // Every variant answers 502 on the response side, unconditionally: the
            // client's request may have been perfect and the upstream is what
            // misbehaved.
            assert_eq!(
                err.status(HandshakeSide::Response),
                502,
                "{err:?} status on HandshakeSide::Response must always be 502"
            );
            // `Display` must actually render something: the empty string is exactly
            // what `replace fmt -> Ok(Default::default())` leaves behind.
            let rendered = err.to_string();
            assert!(
                !rendered.is_empty(),
                "{err:?} rendered an empty Display string"
            );
            labels.push(label);
        }

        labels.sort_unstable();
        for pair in labels.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate metric label: {}", pair[0]);
        }
        for label in &labels {
            assert!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{label:?} is not snake_case"
            );
        }
    }

    /// A handful of exact `Display` strings, spot-checked verbatim rather than only
    /// asserted non-empty: proves the message TEXT itself, not merely that some
    /// text exists.
    #[test]
    fn handshake_error_display_text_is_exact() {
        assert_eq!(
            HandshakeError::UpgradeTokenNotWebsocket.to_string(),
            "upgrade token is not websocket"
        );
        assert_eq!(
            HandshakeError::ConnectionTokenMissing.to_string(),
            "connection header does not contain the upgrade token"
        );
        assert_eq!(
            HandshakeError::MethodNotGet {
                method: Method::Post
            }
            .to_string(),
            "websocket upgrade method is Post, expected GET"
        );
        assert_eq!(
            HandshakeError::UnsupportedVersion { found: 8 }.to_string(),
            "sec-websocket-version is 8, only 13 is supported"
        );
        assert_eq!(
            HandshakeError::KeyWrongLength { len: 23 }.to_string(),
            "sec-websocket-key is 23 characters, expected 24"
        );
        assert_eq!(
            HandshakeError::NotSwitchingProtocols { status: 200 }.to_string(),
            "upstream answered 200, expected 101"
        );
        assert_eq!(
            HandshakeError::TooManySubprotocols.to_string(),
            "more than 8 subprotocols offered"
        );
        assert_eq!(
            HandshakeError::SubprotocolListTooLong { len: 257 }.to_string(),
            "subprotocol list is 257 bytes, above 256"
        );
    }
}
