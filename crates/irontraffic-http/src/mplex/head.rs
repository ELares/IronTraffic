// SPDX-License-Identifier: MIT OR Apache-2.0
//! `MplexHeadBuilder`, the sink an HPACK or QPACK decoder pushes each decoded
//! `(name, value)` pair into, plus `MplexTrailerBuilder` and
//! `MplexResponseBuilder`.
//!
//! This is the HTTP/2 and HTTP/3 twin of `h1::canonicalize_request`: it
//! validates pseudo-headers and fields against RFC 9113 Section 8.2 and RFC
//! 9114 Section 4.3, joins `cookie` crumbs, charges the uncompressed
//! header-list budget, and produces a `CanonicalRequest` identical in shape
//! to the one the HTTP/1 path produces. The same field validation tables
//! apply, so a field HTTP/2 accepts and HTTP/1 refuses does not exist.
//!
//! **Charge before store.** Every pair pushed is charged against
//! `HeaderListBudget` before it is stored anywhere and before any `cookie`
//! join: that is what stops a decompression bomb from being bounded by the
//! input rather than by the limit (Envoy CVE-2026-47774's lesson, for the
//! cookie case specifically).
//!
//! **No lifetime parameters.** `MplexHeadBuilder`, `MplexTrailerBuilder` and
//! `MplexResponseBuilder` carry none, and both of the reasons are load
//! bearing:
//!
//! - `FieldSectionBuilder` holds no borrow of the arena, so `push(&mut self,
//!   arena, ..)` and `finish(self, arena)` can both take the SAME `&mut
//!   BytesMut`. A `FieldSectionBuilder<'c>` constructed from `&'c mut
//!   BytesMut` would make a later `finish` a second mutable borrow of a
//!   buffer the builder already holds, which does not compile.
//! - Pseudo-header values and `cookie` crumb bytes go into the builder's own
//!   `scratch`, NOT into `arena`. If they went into `arena`, `finish` would
//!   have to read them while pushing the joined `cookie` field into the same
//!   arena, which is an aliasing conflict, and the field section's own
//!   `split_off` in `finish` would move those bytes out from under the
//!   recorded offsets. One owned buffer, bounded by the same header-list
//!   budget as everything else, removes both problems for at most one
//!   allocation per stream that carries a pseudo-header.
//!
//! **Underscore policy is not consulted here.** `field::validate_name` takes
//! no `UnderscorePolicy` and refuses `_` unconditionally on every version,
//! because on a multiplexed protocol there is no case folding to do. This
//! path uses `FieldSectionBuilder::push`, never the normalizing entry point:
//! refusing outright achieves the fail-closed direction `UnderscorePolicy`
//! exists for on HTTP/1 more simply, since there is nothing to normalize.
//! `MplexContext::underscores` is carried for parity with the HTTP/1 context
//! type and for the caller's own diagnostics; it is never read here.
//!
//! **Trailers are a separate builder.** A trailer section on HTTP/2 or
//! HTTP/3 arrives as a SECOND header block, in a separate frame, after the
//! request head has already been finished and dispatched. `finish` consumes
//! `MplexHeadBuilder`, and a trailer field pushed into it would land in
//! `CanonicalRequest::headers`, which is precisely the merge this product
//! forbids: a request that passed an `Authorization`-based policy on its
//! header block must not be able to add a `host`, a `content-length` or a
//! `cookie` afterwards. `MplexTrailerBuilder` has its own, fresh
//! `HeaderListBudget` and its own `FieldSection`; there is no method
//! anywhere in this file that merges the two.

use std::net::SocketAddr;

use bytes::BytesMut;

use crate::authority::reconcile_authority;
use crate::canonical::{CanonicalRequest, CanonicalRequestBuilder, CanonicalResponse};
use crate::error::RejectReason;
use crate::expect::check_expect;
use crate::field::{self, UnderscorePolicy};
use crate::forwarded::ForwardedChain;
use crate::framing::{OtherCodings, RequestFraming, resolve_request_framing};
use crate::h1::chunked::trailer_denied;
use crate::hlist::{CookieAccumulator, HeaderListBudget};
use crate::known::{self, KnownHeader};
use crate::limits::ClampedLimits;
use crate::path::{NormalizedPath, PathPolicy, RawQuery, TargetForm};
use crate::peer::{TrustPolicy, resolve_identity};
use crate::response::resolve_response_framing;
use crate::scalar::{Method, Scheme, StatusCode, WireVersion};
use crate::section::{FieldSection, FieldSectionBuilder};
use crate::strip;

/// Everything about the connection and the configuration that a decoded header
/// block does not carry.
///
/// The same shape as `h1::canonicalize::H1Context` minus `default_authority`
/// and `forward_proxy` (neither applies to a multiplexed protocol) plus
/// nothing else; kept as its own type here to avoid coupling the two
/// assembly functions.
#[derive(Clone, Debug)]
pub struct MplexContext<'c> {
    /// Limits for this listener.
    pub limits: ClampedLimits,
    /// Path normalization policy.
    pub path_policy: PathPolicy,
    /// Transfer-coding policy (used only to reject; H2 and H3 never carry a
    /// coding).
    pub codings: OtherCodings,
    /// Underscore policy. Carried for parity with `H1Context` and for the
    /// caller's diagnostics; the builder does NOT consult it, because
    /// `field::validate_name` refuses `_` unconditionally on every version
    /// and this path never normalizes a name.
    pub underscores: UnderscorePolicy,
    /// Scheme of the listener, used for `CONNECT` where `:scheme` is absent.
    pub scheme: Scheme,
    /// The socket or QUIC peer address.
    pub socket_peer: SocketAddr,
    /// A validated PROXY protocol source address, when the listener uses it.
    pub proxy_proto: Option<SocketAddr>,
    /// How much of the forwarding chain to believe.
    pub trust: &'c TrustPolicy,
    /// True when a route-compiled feature will buffer the body.
    pub will_buffer_body: bool,
}

/// Byte ranges of the pseudo-header values, into the builder's own `scratch`.
///
/// Five named `Option` fields, not a `HashMap`: there are exactly five
/// request pseudo-headers, and a map would pay a hash for a five-way
/// choice a `match` on the field name already makes for free.
#[derive(Copy, Clone, Debug, Default)]
struct PseudoSlots {
    method: Option<(u32, u16)>,
    scheme: Option<(u32, u16)>,
    authority: Option<(u32, u16)>,
    path: Option<(u32, u16)>,
    protocol: Option<(u32, u16)>,
}

/// Reads back the `len` bytes recorded at `off` in `scratch`, or `None` if
/// that range is not entirely within `scratch`.
///
/// `off as usize` and `len as usize` are widening casts (both source types
/// are narrower than `usize` on every platform this workspace targets), so
/// neither can lose data; `checked_add` bounds the sum rather than a bare
/// `+`, which this crate denies (`clippy::arithmetic_side_effects`).
fn scratch_slice(scratch: &[u8], off: u32, len: u32) -> Option<&[u8]> {
    let end = (off as usize).checked_add(len as usize)?;
    scratch.get((off as usize)..end)
}

/// Reads back an optional pseudo-header slot. `Ok(None)` when the slot was
/// never set (the pseudo-header was absent); `Err(HeaderListTooLarge)` when
/// it was set but the recorded range cannot be read back, which is a
/// programming error in this file rather than a legitimate absence: a range
/// that does not read back REFUSES the request rather than resolving to an
/// empty or truncated value, because a pseudo-header value can select a
/// route, an upstream, or the shape of the serialized request.
fn pseudo_value(scratch: &[u8], slot: Option<(u32, u16)>) -> Result<Option<&[u8]>, RejectReason> {
    match slot {
        None => Ok(None),
        Some((off, len)) => scratch_slice(scratch, off, u32::from(len))
            .map(Some)
            .ok_or(RejectReason::HeaderListTooLarge),
    }
}

/// Steps 4 and 5 of `MplexHeadBuilder::finish` and `MplexResponseBuilder`'s
/// analogous scheme handling: validates `:scheme` is exactly `http` or
/// `https` (ASCII case insensitive) and then normalizes `:path`, shared by
/// the extended-CONNECT and the ordinary-request branches of `finish` (the
/// only two branches where `:scheme` and `:path` are both required and both
/// go through the identical HTTP/1 path grammar).
///
/// # Errors
/// `PseudoHeaderUnknown` for a `:scheme` other than `http` or `https`;
/// `PathEmpty` for an empty `:path`; `TargetFormInvalid` for `:path = "*"` on
/// a method other than `OPTIONS`; every error `NormalizedPath::parse_into`
/// can return for any other `:path` value.
fn resolve_scheme_and_path(
    scheme_bytes: &[u8],
    path_bytes: &[u8],
    method: Method,
    ctx: &MplexContext<'_>,
    arena: &mut BytesMut,
) -> Result<(Scheme, NormalizedPath, Option<RawQuery>, TargetForm), RejectReason> {
    let scheme = if scheme_bytes.eq_ignore_ascii_case(b"http") {
        Scheme::Http
    } else if scheme_bytes.eq_ignore_ascii_case(b"https") {
        Scheme::Https
    } else {
        return Err(RejectReason::PseudoHeaderUnknown);
    };

    if path_bytes.is_empty() {
        return Err(RejectReason::PathEmpty);
    }

    // The RFC 9113 Section 8.3.1 spelling of `OPTIONS *`: `NormalizedPath::parse_into`
    // refuses a bare `*` with `TargetFormInvalid` because origin-form must begin with
    // `/`, so this branch must run BEFORE that call, not fall into it.
    if path_bytes == b"*" {
        return if matches!(method, Method::Options) {
            Ok((scheme, NormalizedPath::root(), None, TargetForm::Asterisk))
        } else {
            Err(RejectReason::TargetFormInvalid)
        };
    }

    let (path, query) =
        NormalizedPath::parse_into(path_bytes, &ctx.path_policy, &ctx.limits, arena)?;
    Ok((scheme, path, query, TargetForm::Origin))
}

/// Parses a `:status` value: exactly three ASCII digits in `100..=599`.
///
/// # Errors
/// `PseudoHeaderUnknown` for anything else: the wrong length, a non-digit
/// byte, or a value outside the legal status range.
fn parse_status(value: &[u8]) -> Result<StatusCode, RejectReason> {
    if value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
        return Err(RejectReason::PseudoHeaderUnknown);
    }
    let text = core::str::from_utf8(value).map_err(|_| RejectReason::PseudoHeaderUnknown)?;
    let numeric: u16 = text
        .parse()
        .map_err(|_| RejectReason::PseudoHeaderUnknown)?;
    StatusCode::from_u16(numeric).ok_or(RejectReason::PseudoHeaderUnknown)
}

/// Accumulates one decoded HTTP/2 or HTTP/3 header block into a `CanonicalRequest`.
///
/// The decoder pushes every `(name, value)` pair through `push`, in wire order, then
/// calls `finish`. Every pair is charged against the uncompressed header-list budget
/// BEFORE it is stored and before any `cookie` join.
#[derive(Debug)]
pub struct MplexHeadBuilder {
    budget: HeaderListBudget,
    seen_regular_field: bool,
    pseudo: PseudoSlots,
    cookies: CookieAccumulator,
    fields: FieldSectionBuilder,
    /// Pseudo-header values and `cookie` crumb bytes, owned by the builder. Starts
    /// empty and allocates on the first pseudo-header or `cookie` crumb, which is
    /// bounded by the header-list budget. These do NOT go into `arena`; see the
    /// module documentation for why.
    scratch: BytesMut,
    version: WireVersion,
}

impl MplexHeadBuilder {
    /// A builder whose field section will be written into `arena` from its current end.
    /// `arena` is borrowed only for this call; every later call takes it again.
    #[must_use]
    pub fn new(arena: &BytesMut, limits: &ClampedLimits, version: WireVersion) -> Self {
        MplexHeadBuilder {
            budget: HeaderListBudget::new(limits),
            seen_regular_field: false,
            pseudo: PseudoSlots::default(),
            cookies: CookieAccumulator::new(),
            fields: FieldSectionBuilder::new(arena, limits),
            // 128 bytes covers every pseudo-header value plus one unsplit
            // `cookie` field in this crate's own bench `typical_head()` input
            // (65 bytes total) with headroom, removing most of `scratch`'s
            // own regrowth (issue #867). A fixed, one-time reservation, not a
            // data-dependent one.
            scratch: BytesMut::with_capacity(128),
            version,
        }
    }

    /// Pushes one decoded header. Call once per pair the decoder emits, in wire order.
    ///
    /// Charges the uncompressed header-list budget FIRST, so a decompression bomb is
    /// bounded by the limit rather than by the input size.
    ///
    /// # Errors
    /// `HeaderListTooLarge`, `FieldCountExceeded`, `FieldLineTooLong`, `FieldNameEmpty`,
    /// `FieldNameUppercase`, `FieldNameInvalidByte`, `FieldNameUnderscore`,
    /// `FieldValueInvalidByte`, `FieldValueLeadingWhitespace`,
    /// `FieldValueTrailingWhitespace`, `PseudoHeaderUnknown`, `PseudoHeaderDuplicate`,
    /// `PseudoHeaderAfterField`, `ConnectionSpecificField`, `TeValueNotTrailers`.
    pub fn push(
        &mut self,
        arena: &mut BytesMut,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), RejectReason> {
        // Step 1: charge first, always, before anything else.
        self.budget.charge(name.len(), value.len())?;

        // Step 2.
        if name.is_empty() {
            return Err(RejectReason::FieldNameEmpty);
        }

        // Step 3: a pseudo-header.
        if name.first() == Some(&b':') {
            if self.seen_regular_field {
                return Err(RejectReason::PseudoHeaderAfterField);
            }
            let slot: &mut Option<(u32, u16)> = match name {
                b":method" => &mut self.pseudo.method,
                b":scheme" => &mut self.pseudo.scheme,
                b":authority" => &mut self.pseudo.authority,
                b":path" => &mut self.pseudo.path,
                b":protocol" => &mut self.pseudo.protocol,
                _ => return Err(RejectReason::PseudoHeaderUnknown),
            };
            if slot.is_some() {
                return Err(RejectReason::PseudoHeaderDuplicate);
            }
            // Refuses NUL, CR and LF and (on this multiplexed version) a leading or
            // trailing SP or HTAB: what stops a CRLF-carrying `:path` from becoming
            // two lines in a downgraded HTTP/1 request line.
            field::validate_value(value, self.version)?;
            let off = u32::try_from(self.scratch.len()).unwrap_or(u32::MAX);
            self.scratch.extend_from_slice(value);
            let len = u16::try_from(value.len()).map_err(|_| RejectReason::FieldLineTooLong)?;
            *slot = Some((off, len));
            return Ok(());
        }

        // Step 4: a regular field.
        self.seen_regular_field = true;

        // 4a. Uppercase is refused, never folded: on HTTP/2 and HTTP/3 there is no
        // case-insensitive backend to fold toward.
        for &b in name {
            if b.is_ascii_uppercase() {
                return Err(RejectReason::FieldNameUppercase);
            }
        }
        // 4b. `_` is refused unconditionally: `validate_name` takes no
        // `UnderscorePolicy`, so `MplexContext::underscores` is never consulted here.
        field::validate_name(name, self.version)?;
        // 4c.
        field::validate_value(value, self.version)?;

        // 4d. `strip::is_connection_specific`, never a named `KnownHeader` variant
        // this file may not read directly: covers exactly `Connection`,
        // `ProxyConnection`, `KeepAlive`, the H2.TE-relevant hop-by-hop framing
        // field, `Upgrade` and `Http2Settings`.
        let known = known::classify(name);
        if strip::is_connection_specific(known) {
            return Err(RejectReason::ConnectionSpecificField);
        }

        // 4e.
        if known == KnownHeader::Te && !value.eq_ignore_ascii_case(b"trailers") {
            return Err(RejectReason::TeValueNotTrailers);
        }

        // 4f. `cookie` crumbs are recorded, not pushed as a field: RFC 9113 Section
        // 8.2.3 lets a client split `cookie` so each crumb can be HPACK-indexed.
        if known == KnownHeader::Cookie {
            let off = u32::try_from(self.scratch.len()).unwrap_or(u32::MAX);
            self.scratch.extend_from_slice(value);
            let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
            self.cookies.push(off, len)?;
            return Ok(());
        }

        // 4g.
        self.fields.push(arena, name, value)
    }

    /// Completes the head into a canonical request and the request-target form.
    ///
    /// The form is `Authority` for `CONNECT` without `:protocol`, `Asterisk` for
    /// `:path = "*"` on `OPTIONS`, and `Origin` otherwise. It is returned rather than
    /// stored on `CanonicalRequest` for the same reason `h1::canonicalize::canonicalize_request`
    /// returns it: it is a property of the wire representation, and `OPTIONS /` and
    /// `OPTIONS *` serialize differently, as does a `CONNECT` request, which must
    /// serialize in authority-form.
    ///
    /// # Errors
    /// `PseudoHeaderMissing`, `PseudoHeaderUnknown`, `PseudoProtocolUnsupported`,
    /// `PathEmpty`, `TargetFormInvalid`, `HostDuplicate`, `AuthorityMismatch`,
    /// `ExpectUnsupported`, plus every error the path, authority, framing,
    /// forwarding-chain and strip steps can return.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear eleven-step assembly over one head block, mirroring \
                  h1::canonicalize::canonicalize_request; splitting it would scatter \
                  the step ordering the design and its edge cases both depend on \
                  across several functions with no clearer seam"
    )]
    pub fn finish(
        mut self,
        ctx: &MplexContext<'_>,
        arena: &mut BytesMut,
    ) -> Result<(CanonicalRequest, TargetForm), RejectReason> {
        let pseudo = self.pseudo;
        let version = self.version;

        // Step 1: cookie join. Charging already happened per crumb; the join
        // charges nothing.
        match self.cookies.len() {
            0 => {}
            1 => {
                // One crumb: no separator, no join buffer, no allocation. A crumb
                // that does not read back REFUSES the request: `cookie` is
                // authorization data, and a silently emptied one is a different
                // request from the one the peer sent. `crumbs().first()` rather
                // than `crumbs()[0]`: this crate denies `clippy::indexing_slicing`.
                let Some(&(off, len)) = self.cookies.crumbs().first() else {
                    return Err(RejectReason::HeaderListTooLarge);
                };
                let v = scratch_slice(&self.scratch, off, len)
                    .ok_or(RejectReason::HeaderListTooLarge)?;
                self.fields.push(arena, b"cookie", v)?;
            }
            _ => {
                let mut joined = BytesMut::with_capacity(self.cookies.joined_len() as usize);
                self.cookies.join_into(&self.scratch, &mut joined)?;
                self.fields.push(arena, b"cookie", &joined)?;
            }
        }

        let mut fields = self.fields.finish(arena);
        // `self.fields.finish(arena)` calls `arena.split_off(self.base)`
        // internally, which hands the entire remaining spare capacity of
        // `arena` to the `Bytes` it returns and leaves `arena` with capacity
        // exactly equal to its current length. Every write into `arena`
        // after this point (`resolve_scheme_and_path`'s path normalization,
        // `reconcile_authority`'s authority write, `ForwardedChain::from_section`'s
        // write) would otherwise start from zero spare capacity and
        // reallocate independently; this single reserve lets those three
        // writes share the same growth (issue #867).
        arena.reserve(256);

        // Step 2: method.
        let method_bytes =
            pseudo_value(&self.scratch, pseudo.method)?.ok_or(RejectReason::PseudoHeaderMissing)?;
        let method = Method::parse(method_bytes, &ctx.limits)?;

        let protocol_value = pseudo_value(&self.scratch, pseudo.protocol)?;
        let scheme_value = pseudo_value(&self.scratch, pseudo.scheme)?;
        let path_value = pseudo_value(&self.scratch, pseudo.path)?;

        // Step 3: CONNECT shape, then steps 4 and 5 (scheme and path) for every
        // other shape.
        let (scheme, path, query, form) = match (method.is_connect(), protocol_value) {
            (true, None) => {
                // Plain CONNECT: `:scheme` and `:path` MUST be absent, `:authority`
                // MUST be present. The path becomes root, the query `None`, and the
                // scheme comes from the listener rather than from a pseudo-header.
                if scheme_value.is_some() || path_value.is_some() {
                    return Err(RejectReason::PseudoHeaderUnknown);
                }
                if pseudo.authority.is_none() {
                    return Err(RejectReason::PseudoHeaderMissing);
                }
                (
                    ctx.scheme,
                    NormalizedPath::root(),
                    None,
                    TargetForm::Authority,
                )
            }
            (true, Some(protocol_bytes)) => {
                // Extended CONNECT (RFC 8441): `:scheme`, `:path` and `:authority`
                // MUST all be present.
                let (Some(scheme_bytes), Some(path_bytes)) = (scheme_value, path_value) else {
                    return Err(RejectReason::PseudoHeaderMissing);
                };
                if pseudo.authority.is_none() {
                    return Err(RejectReason::PseudoHeaderMissing);
                }
                // RFC 9220 Section 3: an unsupported `:protocol` value on an
                // otherwise well-formed extended CONNECT request is a CONTENT
                // error (501), never `PseudoHeaderUnknown` (400): the request is a
                // well-formed attempt naming a protocol we do not support, not a
                // malformed message.
                if !protocol_bytes.eq_ignore_ascii_case(b"websocket") {
                    return Err(RejectReason::PseudoProtocolUnsupported);
                }
                resolve_scheme_and_path(scheme_bytes, path_bytes, method, ctx, arena)?
            }
            (false, Some(_)) => {
                // RFC 8441 Section 4: `:protocol` may only appear on CONNECT.
                // Accepting and ignoring it here would mean the extended-CONNECT
                // bridge and the ordinary request path disagree about what the
                // message is.
                return Err(RejectReason::PseudoHeaderUnknown);
            }
            (false, None) => {
                let (Some(scheme_bytes), Some(path_bytes)) = (scheme_value, path_value) else {
                    return Err(RejectReason::PseudoHeaderMissing);
                };
                resolve_scheme_and_path(scheme_bytes, path_bytes, method, ctx, arena)?
            }
        };

        // Step 6: authority.
        let host_field = fields
            .get_unique_known(KnownHeader::Host)
            .map_err(|_| RejectReason::HostDuplicate)?;
        let pseudo_authority = pseudo_value(&self.scratch, pseudo.authority)?;
        let authority = reconcile_authority(
            host_field,
            pseudo_authority,
            scheme,
            version,
            &ctx.limits,
            arena,
        )?;

        // Step 7: framing.
        let framing = resolve_request_framing(&method, version, &fields, ctx.codings)?;
        // GH-842: `resolve_request_framing`'s "neither field present" branch
        // returns `Streamed` on a multiplexed version regardless of method, which
        // is correct for the ordinary streaming POST that branch's own comment
        // describes but wrong for CONNECT: RFC 9113 Section 8.5 gives a CONNECT
        // request no body at the framing layer, the same as HTTP/1.1's CONNECT
        // (whose own, unconditional "neither field present" branch already
        // resolves to `Empty` for exactly this input; see
        // `h1::canonicalize::tests::corpus_table` case 11). Left as `Streamed`,
        // `CanonicalRequestBuilder::build`'s CONNECT invariant below would refuse
        // every ordinary CONNECT tunnel over HTTP/2 or HTTP/3 with
        // `BodyNotAllowedForMethod`. This remap is provably equivalent to fixing
        // `resolve_request_framing` itself for every input it can produce: a
        // `transfer-encoding` or a `content-length` on CONNECT is already resolved
        // by that function's own earlier steps and never reaches here as
        // `Streamed`, so CONNECT can only arrive at `Streamed` through the gap
        // this comment describes. It reads neither the length field name nor the
        // transfer-coding field name directly, so it is not a second, unreviewed
        // reader of either one (the `framing-fields-confined` invariant lint).
        // Filed as GH-842 against `request-framing-resolution` (#27); delete this
        // remap once that issue lands the real fix there.
        let framing = if method.is_connect() && matches!(framing, RequestFraming::Streamed) {
            RequestFraming::Empty
        } else {
            framing
        };

        // Step 8: forwarding chain and identity.
        let chain = ForwardedChain::from_section(&fields, &ctx.limits, arena)?;
        let peer = resolve_identity(ctx.socket_peer, ctx.proxy_proto, &chain, ctx.trust);

        // Step 9: Expect. On H2 and H3 there is no 100-continue handshake to run
        // from this builder, so the result is used only to refuse a bad value; the
        // action itself is not returned.
        check_expect(&fields, ctx.will_buffer_body)?;

        // Step 10: strip hop-by-hop, identity and reserved-prefix fields. Must run
        // AFTER steps 7 through 9, which read fields this step deletes.
        strip::strip_ingress(&mut fields, &ctx.limits)?;

        // Step 11: build.
        let request = CanonicalRequestBuilder::new()
            .method(method)
            .scheme(scheme)
            .authority(authority)
            .path(path, query)
            .headers(fields)
            .framing(framing)
            .version(version)
            .peer(peer)
            .build()?;

        Ok((request, form))
    }

    /// Uncompressed bytes charged so far.
    #[must_use]
    pub const fn charged(&self) -> u64 {
        self.budget.used()
    }
}

/// The guarded `charged()` bound: true up to and including the push whose
/// OWN charge first crosses `limit`, not for any push after that.
///
/// `HeaderListBudget::charge` keeps adding to `used` on every later call
/// once `count` is still within `max_field_count`, so `used` is not capped
/// at `limit + one entry`, it is only bounded up to the crossing charge.
/// Returns `None` when the guard does not apply: `charged_before` was
/// already past `limit` going into this push, so this push's own bound is
/// not checked (the OTHER invariant, [`push_poisons_budget`], is what
/// proves nothing further gets stored past that point).
///
/// Shared by this crate's own
/// `header_list_budget_used_keeps_growing_past_the_first_crossing`
/// regression test and `fuzz_targets/fuzz_mplex_head.rs`'s per-push
/// assertion, on purpose: the two check the SAME arithmetic fact about
/// `HeaderListBudget::charge`, and one authoritative copy is what stops the
/// two from silently drifting out of sync with each other or with `charge`'s
/// own step order.
#[must_use]
pub fn guarded_charged_bound(
    charged_before: u64,
    limit: u64,
    name_len: usize,
    value_len: usize,
) -> Option<u64> {
    if charged_before > limit {
        return None;
    }
    let entry = u64::try_from(name_len)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(value_len).unwrap_or(u64::MAX))
        .saturating_add(32);
    Some(limit.saturating_add(entry))
}

/// Whether a `push` result poisons the header-list budget for every LATER
/// push in the same sequence.
///
/// Terminal: `HeaderListTooLarge` (`HeaderListBudget::charge`'s `used` is
/// monotonically non-decreasing, so once `used > limit` it stays `> limit`
/// forever), and a `FieldCountExceeded` that the budget's OWN field-count
/// ceiling raised (`charge`'s step 1, the count check, which returns before
/// `used` is touched -- so `charged_after == charged_before` for THIS push).
///
/// NOT terminal: a `FieldCountExceeded` from [`CookieAccumulator`]'s own,
/// independent `MAX_COOKIE_CRUMBS` (256) ceiling. That ceiling is reached
/// only for a `cookie` push whose OWN charge against the header-list budget
/// already succeeded (`push`'s step 1 runs `self.budget.charge` first,
/// unconditionally, before the accumulator is ever consulted at step 4f), so
/// `charged_after > charged_before` on THIS push. The budget's own `used`
/// and `count` are untouched by the accumulator's refusal, so a later,
/// non-cookie push can still be charged and stored -- see
/// `cookie_crumb_flood_is_bounded`'s bound 3, which constructs exactly that
/// push sequence, and
/// `field_count_exceeded_from_cookie_accumulator_does_not_poison_the_budget`
/// below, which pushes one step past it.
///
/// Shared with `fuzz_targets/fuzz_mplex_head.rs` for the same reason
/// [`guarded_charged_bound`] above is: one authoritative copy of the
/// distinction, not two independently written copies that can silently
/// disagree.
#[must_use]
pub fn push_poisons_budget(
    result: &Result<(), RejectReason>,
    charged_before: u64,
    charged_after: u64,
) -> bool {
    match result {
        Err(RejectReason::HeaderListTooLarge) => true,
        Err(RejectReason::FieldCountExceeded) => charged_after == charged_before,
        _ => false,
    }
}

/// Accumulates a decoded HTTP/2 or HTTP/3 TRAILER block. Separate from
/// `MplexHeadBuilder` because a trailer section is a separate header block that
/// arrives after the head was dispatched, and because its fields must never reach
/// `CanonicalRequest::headers`. There is deliberately no method on this type, and none
/// on `MplexHeadBuilder`, that merges the two.
#[derive(Debug)]
pub struct MplexTrailerBuilder {
    /// A FRESH budget, never the head block's. A message with trailers can therefore
    /// charge up to `2 * max_header_list_bytes` in total, which is the number to size
    /// against.
    budget: HeaderListBudget,
    fields: FieldSectionBuilder,
    version: WireVersion,
}

impl MplexTrailerBuilder {
    /// A trailer builder with a FRESH header-list budget, never the head block's.
    #[must_use]
    pub fn new(arena: &BytesMut, limits: &ClampedLimits, version: WireVersion) -> Self {
        MplexTrailerBuilder {
            budget: HeaderListBudget::new(limits),
            fields: FieldSectionBuilder::new(arena, limits),
            version,
        }
    }

    /// Pushes one decoded trailer field. Refuses pseudo-headers and the 18-entry
    /// trailer deny-list, with the same field validation as the head path.
    ///
    /// # Errors
    /// `HeaderListTooLarge`, `FieldCountExceeded`, `FieldLineTooLong`,
    /// `FieldNameEmpty`, `PseudoHeaderInTrailer`, `FieldNameUppercase`,
    /// `FieldNameInvalidByte`, `FieldNameUnderscore`, `FieldValueInvalidByte`,
    /// `FieldValueLeadingWhitespace`, `FieldValueTrailingWhitespace`,
    /// `ConnectionSpecificField`, `TrailerFieldForbidden`.
    pub fn push(
        &mut self,
        arena: &mut BytesMut,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), RejectReason> {
        self.budget.charge(name.len(), value.len())?;

        if name.is_empty() {
            return Err(RejectReason::FieldNameEmpty);
        }
        if name.first() == Some(&b':') {
            return Err(RejectReason::PseudoHeaderInTrailer);
        }

        for &b in name {
            if b.is_ascii_uppercase() {
                return Err(RejectReason::FieldNameUppercase);
            }
        }
        field::validate_name(name, self.version)?;
        field::validate_value(value, self.version)?;

        let known = known::classify(name);
        if strip::is_connection_specific(known) {
            return Err(RejectReason::ConnectionSpecificField);
        }
        if trailer_denied(known) {
            return Err(RejectReason::TrailerFieldForbidden);
        }

        self.fields.push(arena, name, value)
    }

    /// The validated trailer section, as its OWN value. There is no method anywhere
    /// that merges this into a `CanonicalRequest`'s or `CanonicalResponse`'s headers.
    #[must_use]
    pub fn finish(self, arena: &mut BytesMut) -> FieldSection {
        self.fields.finish(arena)
    }
}

/// Accumulates one decoded HTTP/2 or HTTP/3 response header block into a
/// `CanonicalResponse`.
///
/// The same shape as `MplexHeadBuilder` for a response: `:status` is the only
/// permitted pseudo-header, it is mandatory, and the four request
/// pseudo-headers are refused as `PseudoHeaderUnknown`.
#[derive(Debug)]
pub struct MplexResponseBuilder {
    budget: HeaderListBudget,
    seen_regular_field: bool,
    status: Option<(u32, u16)>,
    fields: FieldSectionBuilder,
    /// The `:status` value, owned by the builder. Never `arena`, for the same
    /// reason `MplexHeadBuilder::scratch` is not `arena`.
    scratch: BytesMut,
    version: WireVersion,
}

impl MplexResponseBuilder {
    /// A builder whose field section will be written into `arena` from its current end.
    #[must_use]
    pub fn new(arena: &BytesMut, limits: &ClampedLimits, version: WireVersion) -> Self {
        MplexResponseBuilder {
            budget: HeaderListBudget::new(limits),
            seen_regular_field: false,
            status: None,
            fields: FieldSectionBuilder::new(arena, limits),
            scratch: BytesMut::new(),
            version,
        }
    }

    /// Pushes one decoded header.
    ///
    /// # Errors
    /// As `MplexHeadBuilder::push`, with `:status` permitted and the four request
    /// pseudo-headers refused as `PseudoHeaderUnknown`.
    pub fn push(
        &mut self,
        arena: &mut BytesMut,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), RejectReason> {
        self.budget.charge(name.len(), value.len())?;

        if name.is_empty() {
            return Err(RejectReason::FieldNameEmpty);
        }

        if name.first() == Some(&b':') {
            if self.seen_regular_field {
                return Err(RejectReason::PseudoHeaderAfterField);
            }
            if name != b":status" {
                return Err(RejectReason::PseudoHeaderUnknown);
            }
            if self.status.is_some() {
                return Err(RejectReason::PseudoHeaderDuplicate);
            }
            field::validate_value(value, self.version)?;
            let off = u32::try_from(self.scratch.len()).unwrap_or(u32::MAX);
            self.scratch.extend_from_slice(value);
            let len = u16::try_from(value.len()).map_err(|_| RejectReason::FieldLineTooLong)?;
            self.status = Some((off, len));
            return Ok(());
        }

        self.seen_regular_field = true;

        for &b in name {
            if b.is_ascii_uppercase() {
                return Err(RejectReason::FieldNameUppercase);
            }
        }
        field::validate_name(name, self.version)?;
        field::validate_value(value, self.version)?;

        let known = known::classify(name);
        if strip::is_connection_specific(known) {
            return Err(RejectReason::ConnectionSpecificField);
        }
        if known == KnownHeader::Te && !value.eq_ignore_ascii_case(b"trailers") {
            return Err(RejectReason::TeValueNotTrailers);
        }

        self.fields.push(arena, name, value)
    }

    /// Completes the head into a canonical response.
    ///
    /// # Errors
    /// `PseudoHeaderMissing` when `:status` is absent, `PseudoHeaderUnknown` for a
    /// malformed status, plus every error `resolve_response_framing` and
    /// `CanonicalResponse::new` can return.
    pub fn finish(
        self,
        request_method: &Method,
        ctx: &MplexContext<'_>,
        arena: &mut BytesMut,
    ) -> Result<CanonicalResponse, RejectReason> {
        let status_bytes =
            pseudo_value(&self.scratch, self.status)?.ok_or(RejectReason::PseudoHeaderMissing)?;
        let status = parse_status(status_bytes)?;

        let mut fields = self.fields.finish(arena);
        let framing =
            resolve_response_framing(status, request_method, self.version, &fields, ctx.codings)?;
        strip::strip_response(&mut fields, &ctx.limits)?;

        CanonicalResponse::new(status, fields, framing, self.version)
    }
}

#[cfg(test)]
#[allow(
    clippy::too_many_lines,
    reason = "a corpus table naming every edge case by number; splitting it would break \
              the 1:1 mapping the issue's own edge-case list depends on"
)]
mod tests {
    use super::{
        MplexContext, MplexHeadBuilder, MplexResponseBuilder, MplexTrailerBuilder, RejectReason,
        guarded_charged_bound, push_poisons_budget,
    };
    use crate::canonical::CanonicalRequest;
    use crate::field::UnderscorePolicy;
    use crate::framing::{OtherCodings, RequestFraming};
    use crate::h1::H1Parser;
    use crate::h1::canonicalize::{H1Context, canonicalize_request};
    use crate::known;
    use crate::limits::Limits;
    use crate::path::{PathPolicy, TargetForm};
    use crate::peer::TrustPolicy;
    use crate::scalar::{Method, ParseStatus, Scheme, WireVersion};
    use crate::strip;
    use bytes::BytesMut;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const DEFAULT_TRUST: TrustPolicy = TrustPolicy::None;

    fn ctx() -> MplexContext<'static> {
        MplexContext {
            limits: Limits::DEFAULT.clamped(),
            path_policy: PathPolicy::DEFAULT,
            codings: OtherCodings::Reject,
            underscores: UnderscorePolicy::Reject,
            scheme: Scheme::Https,
            socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            proxy_proto: None,
            trust: &DEFAULT_TRUST,
            will_buffer_body: false,
        }
    }

    /// Pushes `seq` into a fresh `MplexHeadBuilder` and calls `finish` with the
    /// default context, stopping at the first `push` error.
    fn run(seq: &[(&[u8], &[u8])]) -> Result<(CanonicalRequest, TargetForm), RejectReason> {
        let ctx = ctx();
        let mut arena = BytesMut::new();
        let mut builder = MplexHeadBuilder::new(&arena, &ctx.limits, WireVersion::H2);
        for &(name, value) in seq {
            builder.push(&mut arena, name, value)?;
        }
        builder.finish(&ctx, &mut arena)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Expected {
        Err(RejectReason),
        Ok {
            path: &'static [u8],
            query: Option<&'static [u8]>,
            authority: &'static [u8],
            scheme: Scheme,
            form: TargetForm,
        },
    }

    fn assert_case(seq: &[(&[u8], &[u8])], expected: &Expected) {
        let got = run(seq);
        match (expected, got) {
            (Expected::Err(want), Err(got_err)) => {
                assert_eq!(*want, got_err, "for {seq:?}");
            }
            (
                Expected::Ok {
                    path,
                    query,
                    authority,
                    scheme,
                    form,
                },
                Ok((req, got_form)),
            ) => {
                assert_eq!(req.path.as_bytes(), *path, "path mismatch for {seq:?}");
                assert_eq!(
                    req.query.as_ref().map(crate::path::RawQuery::as_bytes),
                    *query,
                    "query mismatch for {seq:?}"
                );
                assert_eq!(
                    req.authority.host(),
                    *authority,
                    "authority mismatch for {seq:?}"
                );
                assert_eq!(req.scheme, *scheme, "scheme mismatch for {seq:?}");
                assert_eq!(got_form, *form, "form mismatch for {seq:?}");
            }
            (want, got) => panic!("for {seq:?}: expected {want:?}, got {got:?}"),
        }
    }

    /// Test 1. A table of `(push_sequence, expected)` covering edge cases 1
    /// through 50 except 40 through 42c (covered by `trailers_are_a_separate_section`)
    /// and the ones covered more precisely by a dedicated test named in a comment on
    /// each row.
    #[test]
    fn corpus_table() {
        // Edge case 1.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b"host", b"a"),
            ],
            &Expected::Ok {
                path: b"/",
                query: None,
                authority: b"a",
                scheme: Scheme::Https,
                form: TargetForm::Origin,
            },
        );
        // Edge case 2.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"/"),
            ],
            &Expected::Ok {
                path: b"/",
                query: None,
                authority: b"a",
                scheme: Scheme::Https,
                form: TargetForm::Origin,
            },
        );
        // Edge case 3: no `:authority` and no `host`.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
            ],
            &Expected::Err(RejectReason::PseudoHeaderMissing),
        );
        // Edge case 4: no `:scheme`.
        assert_case(
            &[(b":method", b"GET"), (b":path", b"/")],
            &Expected::Err(RejectReason::PseudoHeaderMissing),
        );
        // Edge case 5: no `:method`.
        assert_case(
            &[(b":scheme", b"https"), (b":path", b"/")],
            &Expected::Err(RejectReason::PseudoHeaderMissing),
        );
        // Edge case 6: empty `:path`.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b""),
            ],
            &Expected::Err(RejectReason::PathEmpty),
        );
        // Edge case 12: `:scheme ftp`.
        assert_case(
            &[(b":method", b"GET"), (b":scheme", b"ftp"), (b":path", b"/")],
            &Expected::Err(RejectReason::PseudoHeaderUnknown),
        );
        // Edge case 13: `:scheme HTTPS` (case insensitive).
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"HTTPS"),
                (b":path", b"/"),
                (b":authority", b"a"),
            ],
            &Expected::Ok {
                path: b"/",
                query: None,
                authority: b"a",
                scheme: Scheme::Https,
                form: TargetForm::Origin,
            },
        );
        // Edge case 30: leading SP in a field value.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"/"),
                (b"x", b" v"),
            ],
            &Expected::Err(RejectReason::FieldValueLeadingWhitespace),
        );
        // Edge case 31: trailing SP in a field value.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"/"),
                (b"x", b"v "),
            ],
            &Expected::Err(RejectReason::FieldValueTrailingWhitespace),
        );
        // Edge case 32: NUL in a field value.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"/"),
                (b"x", b"v\0"),
            ],
            &Expected::Err(RejectReason::FieldValueInvalidByte),
        );
        // Edge case 34: an underscore in a field name, under `Reject`.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"/"),
                (b"x_y", b"v"),
            ],
            &Expected::Err(RejectReason::FieldNameUnderscore),
        );
        // Edge case 38: a single pair whose name plus value exceeds
        // `max_header_list_bytes`.
        {
            let huge_value = vec![b'a'; 100_000];
            let seq: [(&[u8], &[u8]); 1] = [(b"x", &huge_value)];
            let got = run(&seq);
            assert!(matches!(got, Err(RejectReason::HeaderListTooLarge)));
        }
        // Edge case 39: three pseudo-headers plus 98 regular fields with
        // `max_field_count: 100` (the shipped default): `HeaderListBudget` charges
        // pseudo-headers too, so the 101st charged pair overall is the 98th
        // regular field (3 pseudo-headers + 97 regular fields already charged =
        // 100, at the cap), and THAT push returns `FieldCountExceeded`.
        {
            let mut arena = BytesMut::new();
            let limits = Limits::DEFAULT.clamped();
            let mut builder = MplexHeadBuilder::new(&arena, &limits, WireVersion::H2);
            builder.push(&mut arena, b":method", b"GET").unwrap();
            builder.push(&mut arena, b":scheme", b"https").unwrap();
            builder.push(&mut arena, b":authority", b"a").unwrap();
            for i in 0..97u32 {
                let name = format!("x-{i:03}");
                builder
                    .push(&mut arena, name.as_bytes(), b"v")
                    .unwrap_or_else(|e| panic!("regular field {i} of 97 must fit, got {e:?}"));
            }
            assert_eq!(
                builder.push(&mut arena, b"x-097", b"v"),
                Err(RejectReason::FieldCountExceeded)
            );
        }
        // Edge case 42b: `:protocol` on a non-CONNECT method.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"/"),
                (b":protocol", b"websocket"),
            ],
            &Expected::Err(RejectReason::PseudoHeaderUnknown),
        );
        // Edge case 43: two `host` fields.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b"host", b"a"),
                (b"host", b"b"),
            ],
            &Expected::Err(RejectReason::HostDuplicate),
        );
        // Edge case 44: `:authority` disagrees with `host`.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"good.com"),
                (b":path", b"/"),
                (b"host", b"evil.com"),
            ],
            &Expected::Err(RejectReason::AuthorityMismatch),
        );
        // Edge case 45: `:authority` and `host` agree after scheme-based port
        // normalization.
        assert_case(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"/"),
                (b"host", b"a:443"),
            ],
            &Expected::Ok {
                path: b"/",
                query: None,
                authority: b"a",
                scheme: Scheme::Https,
                form: TargetForm::Origin,
            },
        );

        // Edge case 47: a response builder accepting a well-formed status.
        {
            let mut arena = BytesMut::new();
            let limits = Limits::DEFAULT.clamped();
            let mut builder = MplexResponseBuilder::new(&arena, &limits, WireVersion::H2);
            builder.push(&mut arena, b":status", b"200").unwrap();
            let resp = builder
                .finish(&Method::Get, &ctx(), &mut arena)
                .expect("well formed response");
            assert_eq!(resp.status.as_u16(), 200);
        }
        // Edge case 48: malformed status values.
        for bad in [&b"20"[..], b"0200", b"99", b"600", b""] {
            let mut arena = BytesMut::new();
            let limits = Limits::DEFAULT.clamped();
            let mut builder = MplexResponseBuilder::new(&arena, &limits, WireVersion::H2);
            builder.push(&mut arena, b":status", bad).unwrap();
            let result = builder.finish(&Method::Get, &ctx(), &mut arena);
            assert!(
                matches!(result, Err(RejectReason::PseudoHeaderUnknown)),
                "status {bad:?} must be refused, got {result:?}"
            );
        }
        // Edge case 49: a request pseudo-header on a response.
        {
            let mut arena = BytesMut::new();
            let limits = Limits::DEFAULT.clamped();
            let mut builder = MplexResponseBuilder::new(&arena, &limits, WireVersion::H2);
            builder.push(&mut arena, b":status", b"200").unwrap();
            assert_eq!(
                builder.push(&mut arena, b":method", b"GET"),
                Err(RejectReason::PseudoHeaderUnknown)
            );
        }
        // Edge case 50: a response with no `:status`.
        {
            let mut arena = BytesMut::new();
            let limits = Limits::DEFAULT.clamped();
            let builder = MplexResponseBuilder::new(&arena, &limits, WireVersion::H2);
            let result = builder.finish(&Method::Get, &ctx(), &mut arena);
            assert!(matches!(result, Err(RejectReason::PseudoHeaderMissing)));
        }
    }

    /// Test 2: edge cases 7 through 11.
    #[test]
    fn pseudo_order_and_duplicates() {
        // 7: a duplicate `:path`.
        assert_eq!(
            run(&[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":path", b"/x"),
            ])
            .map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderDuplicate)
        );
        // 8: a pseudo-header after a regular field.
        assert_eq!(
            run(&[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b"host", b"a"),
                (b":path", b"/"),
            ])
            .map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderAfterField)
        );
        // 9: an unknown pseudo-header.
        assert_eq!(
            run(&[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":bogus", b"x"),
            ])
            .map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderUnknown)
        );
        // 10: `:status` in a request.
        assert_eq!(
            run(&[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":status", b"200"),
            ])
            .map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderUnknown)
        );
        // 11: the bare colon as a name.
        assert_eq!(
            run(&[(b":", b"x")]).map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderUnknown)
        );
    }

    /// Test 3: edge cases 14 through 21, plus 13b and 13c, which are exactly the
    /// three cases where the returned `TargetForm` is not `Origin`. Assert the form,
    /// not only the outcome.
    #[test]
    fn connect_shapes() {
        // 13b: `OPTIONS *` over H2.
        let (req, form) = run(&[
            (b":method", b"OPTIONS"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"*"),
        ])
        .expect("OPTIONS * must be accepted");
        assert_eq!(form, TargetForm::Asterisk);
        assert_eq!(req.path.as_bytes(), b"/");
        assert_eq!(req.query, None);

        // 13c: `*` on a method other than OPTIONS.
        assert_eq!(
            run(&[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"*"),
            ])
            .map(|(_, f)| f),
            Err(RejectReason::TargetFormInvalid)
        );

        // 14: plain CONNECT.
        let (req, form) =
            run(&[(b":method", b"CONNECT"), (b":authority", b"a:443")]).expect("plain CONNECT");
        assert_eq!(form, TargetForm::Authority);
        assert_eq!(req.path.as_bytes(), b"/");
        assert_eq!(req.framing, RequestFraming::Empty);

        // 15: CONNECT with `:path`.
        assert_eq!(
            run(&[
                (b":method", b"CONNECT"),
                (b":authority", b"a:443"),
                (b":path", b"/"),
            ])
            .map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderUnknown)
        );

        // 16: CONNECT with `:scheme`.
        assert_eq!(
            run(&[
                (b":method", b"CONNECT"),
                (b":authority", b"a:443"),
                (b":scheme", b"https"),
            ])
            .map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderUnknown)
        );

        // 17: CONNECT with no `:authority`.
        assert_eq!(
            run(&[(b":method", b"CONNECT")]).map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderMissing)
        );

        // 18: extended CONNECT.
        let (req, form) = run(&[
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/ws"),
        ])
        .expect("extended CONNECT must be accepted");
        assert_eq!(form, TargetForm::Origin);
        assert_eq!(req.path.as_bytes(), b"/ws");

        // 19: `:protocol WEBSOCKET`, case insensitive.
        let (_, form) = run(&[
            (b":method", b"CONNECT"),
            (b":protocol", b"WEBSOCKET"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/ws"),
        ])
        .expect("case-insensitive protocol match");
        assert_eq!(form, TargetForm::Origin);

        // 20: an unsupported `:protocol` value is `PseudoProtocolUnsupported`
        // specifically, not merely `.is_err()`.
        let got = run(&[
            (b":method", b"CONNECT"),
            (b":protocol", b"ftp"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/"),
        ]);
        assert_eq!(
            got.map(|(_, f)| f),
            Err(RejectReason::PseudoProtocolUnsupported)
        );

        // 21: extended CONNECT missing `:scheme`.
        assert_eq!(
            run(&[
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":authority", b"a"),
                (b":path", b"/ws"),
            ])
            .map(|(_, f)| f),
            Err(RejectReason::PseudoHeaderMissing)
        );
    }

    /// Test 4: edge cases 23 through 26, and that `resolve_request_framing` is
    /// therefore never reached with a `transfer-encoding` present.
    #[test]
    fn connection_specific_fields_are_malformed() {
        let base: [(&[u8], &[u8]); 4] = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/"),
        ];
        for (name, value) in [
            (&b"transfer-encoding"[..], &b"chunked"[..]),
            (b"connection", b"keep-alive"),
            (b"upgrade", b"websocket"),
            (b"http2-settings", b"x"),
        ] {
            let mut seq: Vec<(&[u8], &[u8])> = base.to_vec();
            seq.push((name, value));
            assert_eq!(
                run(&seq).map(|(_, f)| f),
                Err(RejectReason::ConnectionSpecificField),
                "{name:?} must be refused"
            );
        }
    }

    /// Test 5: edge cases 27 through 29.
    #[test]
    fn te_only_trailers() {
        let base: [(&[u8], &[u8]); 4] = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/"),
        ];
        // 27: `te: gzip`.
        let mut bad: Vec<(&[u8], &[u8])> = base.to_vec();
        bad.push((b"te", b"gzip"));
        assert_eq!(
            run(&bad).map(|(_, f)| f),
            Err(RejectReason::TeValueNotTrailers)
        );

        // 28: `te: trailers` survives the strip.
        let mut good: Vec<(&[u8], &[u8])> = base.to_vec();
        good.push((b"te", b"trailers"));
        let (req, _) = run(&good).expect("te: trailers must be accepted");
        assert!(matches!(req.headers.get_unique(b"te"), Ok(Some(v)) if v == b"trailers"));

        // 29: `te: Trailers`, case insensitive.
        let mut mixed_case: Vec<(&[u8], &[u8])> = base.to_vec();
        mixed_case.push((b"te", b"Trailers"));
        let (req, _) = run(&mixed_case).expect("te: Trailers must be accepted");
        assert!(req.headers.get_unique(b"te").is_ok());
    }

    /// Test 6: edge case 22, and that the field section does not contain a
    /// lowercased `host`.
    #[test]
    fn uppercase_is_refused_not_folded() {
        let got = run(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":path", b"/"),
            (b"Host", b"a"),
        ]);
        assert_eq!(got.map(|(_, f)| f), Err(RejectReason::FieldNameUppercase));

        // `push` refuses before anything could be written into the field section
        // at all, so an accepted request built from a similar sequence with the
        // uppercase name replaced can never expose a folded `Host`.
        let (req, _) = run(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":path", b"/"),
            (b"host", b"a"),
        ])
        .expect("lowercase host must be accepted");
        assert!(matches!(req.headers.get_unique(b"host"), Ok(Some(v)) if v == b"a"));
    }

    /// Test 7 (and edge case 33): a CRLF in a pseudo-header value.
    #[test]
    fn crlf_in_pseudo_path_is_refused() {
        let got = run(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/a\r\nx: y"),
        ]);
        assert_eq!(
            got.map(|(_, f)| f),
            Err(RejectReason::FieldValueInvalidByte)
        );
    }

    /// Test 8: edge cases 35 and 36, then all three bounds of edge case 37.
    ///
    /// Named `cookie_crumb_flood_is_bounded` (rather than the `cookie_join_and_flood`
    /// name the issue's own `## Tests` section uses for this same test) to satisfy
    /// the `## Acceptance criteria` bullet that greps for that exact name: the two
    /// sections of the issue disagree on the name of this one test.
    #[test]
    fn cookie_crumb_flood_is_bounded() {
        let base: [(&[u8], &[u8]); 4] = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/"),
        ];

        // 35: three crumbs join with "; ".
        let mut three: Vec<(&[u8], &[u8])> = base.to_vec();
        three.push((b"cookie", b"a=1"));
        three.push((b"cookie", b"b=2"));
        three.push((b"cookie", b"c=3"));
        let (req, _) = run(&three).expect("three cookie crumbs must join");
        assert_eq!(
            req.headers.get_unique(b"cookie"),
            Ok(Some(&b"a=1; b=2; c=3"[..]))
        );

        // 36: one crumb, no separator.
        let mut one: Vec<(&[u8], &[u8])> = base.to_vec();
        one.push((b"cookie", b"a=1"));
        let (req, _) = run(&one).expect("one cookie crumb must survive unmodified");
        assert_eq!(req.headers.get_unique(b"cookie"), Ok(Some(&b"a=1"[..])));

        // 37, bound 1: under `Limits::DEFAULT` (`max_field_count: 100`), the 101st
        // charged pair (with three pseudo-headers pushed first, the 98th crumb)
        // returns `FieldCountExceeded`.
        {
            let mut arena = BytesMut::new();
            let limits = Limits::DEFAULT.clamped();
            let mut builder = MplexHeadBuilder::new(&arena, &limits, WireVersion::H2);
            builder.push(&mut arena, b":method", b"GET").unwrap();
            builder.push(&mut arena, b":scheme", b"https").unwrap();
            builder.push(&mut arena, b":authority", b"a").unwrap();
            builder.push(&mut arena, b":path", b"/").unwrap();
            let mut last = Ok(());
            for i in 0..4000u32 {
                last = builder.push(&mut arena, b"cookie", format!("{i}").as_bytes());
                if last.is_err() {
                    break;
                }
            }
            assert_eq!(last, Err(RejectReason::FieldCountExceeded));
        }

        // 37, bound 2: with the count limit raised and `max_header_list_bytes` at
        // 65,536, `charge(6, 1)` costs 39 bytes per crumb, so crumb 1680 is the
        // last accepted and crumb 1681 returns `HeaderListTooLarge`. This is the
        // CVE-2026-47774 regression test at the builder level: charging after
        // concatenation, rather than per crumb, would let all 4000 crumbs through
        // (their joined length is far under 65,536 bytes).
        //
        // Charged against a standalone `HeaderListBudget`, matching
        // `hlist::tests::cookie_crumbs_are_charged_individually`'s own approach and
        // for the same reason that test states: `CookieAccumulator::MAX_COOKIE_CRUMBS`
        // (256) is a separate, independent ceiling far smaller than 1680, so routing
        // 1680 crumbs through the real accumulator (as `MplexHeadBuilder::push`
        // does) would hit THAT ceiling first (see bound 3 below) and would be
        // testing a different defense than this bound is about.
        {
            let mut budget = crate::hlist::HeaderListBudget::with_limits(65_536, u32::MAX);
            let mut accepted = 0u32;
            let mut last = Ok(());
            for _ in 0..4000u32 {
                last = budget.charge(6, 1);
                match last {
                    Ok(()) => accepted += 1,
                    Err(_) => break,
                }
            }
            assert_eq!(accepted, 1680);
            assert_eq!(last, Err(RejectReason::HeaderListTooLarge));
        }

        // 37, bound 3: `CookieAccumulator` refuses its 257th crumb with
        // `FieldCountExceeded` regardless, when the budget's own limits are wide
        // enough that the accumulator's ceiling is the one that fires.
        {
            let mut arena = BytesMut::new();
            let limits = Limits {
                max_field_count: 10_000,
                max_header_list_bytes: Limits::CEILING.max_header_list_bytes,
                ..Limits::DEFAULT
            }
            .clamped();
            let mut builder = MplexHeadBuilder::new(&arena, &limits, WireVersion::H2);
            builder.push(&mut arena, b":method", b"GET").unwrap();
            builder.push(&mut arena, b":scheme", b"https").unwrap();
            builder.push(&mut arena, b":authority", b"a").unwrap();
            builder.push(&mut arena, b":path", b"/").unwrap();
            let mut accepted = 0u32;
            let mut last = Ok(());
            for _ in 0..300u32 {
                last = builder.push(&mut arena, b"cookie", b"1");
                match last {
                    Ok(()) => accepted += 1,
                    Err(_) => break,
                }
            }
            assert_eq!(accepted, 256);
            assert_eq!(last, Err(RejectReason::FieldCountExceeded));
        }

        // In every case above the field section holds no `cookie` field until
        // `finish` joins it, because the join happens in `finish`, never in `push`.
    }

    /// Test 9: the H1 and H2 forms of one logical request produce equal
    /// `CanonicalRequest` values on every field except `version`.
    #[test]
    fn h1_and_h2_agree() {
        let h1_head = b"GET /a/b?x=1 HTTP/1.1\r\nhost: example.com\r\naccept: */*\r\ncontent-length: 3\r\n\r\n";
        let parser = H1Parser::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
        let raw = match parser.parse_request_head(h1_head).unwrap() {
            ParseStatus::Complete { value, .. } => value,
            ParseStatus::Partial => panic!("unexpected partial head"),
        };
        let h1_ctx = H1Context {
            limits: Limits::DEFAULT.clamped(),
            path_policy: PathPolicy::DEFAULT,
            codings: OtherCodings::Reject,
            underscores: UnderscorePolicy::Reject,
            scheme: Scheme::Https,
            socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            proxy_proto: None,
            trust: &DEFAULT_TRUST,
            default_authority: None,
            forward_proxy: false,
            will_buffer_body: false,
        };
        let mut h1_arena = BytesMut::new();
        let (h1_req, _, _) =
            canonicalize_request(&raw, &h1_ctx, &mut h1_arena).expect("well formed HTTP/1 head");

        let h2_pairs: [(&[u8], &[u8]); 7] = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/a/b?x=1"),
            (b"host", b"example.com"),
            (b"accept", b"*/*"),
            (b"content-length", b"3"),
        ];
        // `host` and `:authority` must agree, matching the HTTP/1 side which has
        // only `Host`; both are pushed here so the field multisets line up exactly.
        let (h2_req, _) = run(&h2_pairs).expect("well formed HTTP/2 head");

        assert_eq!(h1_req.method, h2_req.method);
        assert_eq!(h1_req.scheme, h2_req.scheme);
        assert_eq!(h1_req.authority, h2_req.authority);
        assert_eq!(h1_req.path.as_bytes(), h2_req.path.as_bytes());
        assert_eq!(
            h1_req.query.as_ref().map(crate::path::RawQuery::as_bytes),
            h2_req.query.as_ref().map(crate::path::RawQuery::as_bytes)
        );
        assert_eq!(h1_req.framing, h2_req.framing);
        assert_eq!(h1_req.peer.client, h2_req.peer.client);

        let mut h1_fields: Vec<(&[u8], &[u8])> =
            h1_req.headers.iter().map(|(n, v, _)| (n, v)).collect();
        let mut h2_fields: Vec<(&[u8], &[u8])> =
            h2_req.headers.iter().map(|(n, v, _)| (n, v)).collect();
        h1_fields.sort_unstable();
        h2_fields.sort_unstable();
        assert_eq!(h1_fields, h2_fields);

        assert_eq!(h1_req.version, WireVersion::Http11);
        assert_eq!(h2_req.version, WireVersion::H2);
        assert_ne!(h1_req.version, h2_req.version);
    }

    /// Test 10: edge cases 40 through 42c.
    #[test]
    fn trailers_are_a_separate_section() {
        let limits = Limits::DEFAULT.clamped();

        // 40.
        let mut arena = BytesMut::new();
        let mut trailer = MplexTrailerBuilder::new(&arena, &limits, WireVersion::H2);
        assert_eq!(
            trailer.push(&mut arena, b":method", b"GET"),
            Err(RejectReason::PseudoHeaderInTrailer)
        );

        // 41: content-length and every one of the 18 denied names.
        //
        // `transfer-encoding` is a deliberate exception to the uniform
        // `TrailerFieldForbidden` outcome: it is the one name in the 18-entry
        // trailer deny-list that is ALSO in the six-entry connection-specific set
        // (`strip::is_connection_specific`), and `MplexTrailerBuilder::push` runs
        // that check before the trailer deny-list check (the same order
        // `MplexHeadBuilder::push` uses for the identical field validation), so it
        // is refused as `ConnectionSpecificField` instead. Both are 400 Bad
        // Request; only the internal reason and metric label differ, and either
        // one still refuses the field outright rather than forwarding it.
        let denied: [(&[u8], RejectReason); 18] = [
            (b"transfer-encoding", RejectReason::ConnectionSpecificField),
            (b"content-length", RejectReason::TrailerFieldForbidden),
            (b"host", RejectReason::TrailerFieldForbidden),
            (b"expect", RejectReason::TrailerFieldForbidden),
            (b"max-forwards", RejectReason::TrailerFieldForbidden),
            (b"cache-control", RejectReason::TrailerFieldForbidden),
            (b"if-match", RejectReason::TrailerFieldForbidden),
            (b"if-none-match", RejectReason::TrailerFieldForbidden),
            (b"if-modified-since", RejectReason::TrailerFieldForbidden),
            (b"if-unmodified-since", RejectReason::TrailerFieldForbidden),
            (b"if-range", RejectReason::TrailerFieldForbidden),
            (b"range", RejectReason::TrailerFieldForbidden),
            (b"te", RejectReason::TrailerFieldForbidden),
            (b"authorization", RejectReason::TrailerFieldForbidden),
            (b"proxy-authorization", RejectReason::TrailerFieldForbidden),
            (b"cookie", RejectReason::TrailerFieldForbidden),
            (b"set-cookie", RejectReason::TrailerFieldForbidden),
            (b"trailer", RejectReason::TrailerFieldForbidden),
        ];
        for (name, want) in denied {
            let mut arena2 = BytesMut::new();
            let mut t = MplexTrailerBuilder::new(&arena2, &limits, WireVersion::H2);
            assert_eq!(
                t.push(&mut arena2, name, b"x"),
                Err(want),
                "{name:?} must be denied in a trailer"
            );
        }

        // 42: an allowed trailer field, reachable only through the trailer
        // builder's own `finish`, never through a request's headers.
        let mut arena3 = BytesMut::new();
        let mut t = MplexTrailerBuilder::new(&arena3, &limits, WireVersion::H2);
        t.push(&mut arena3, b"x-checksum", b"abc").unwrap();
        let section = t.finish(&mut arena3);
        assert_eq!(section.get_unique(b"x-checksum"), Ok(Some(&b"abc"[..])));

        // 42c: a head block plus a full trailer block both succeed with
        // independent budgets: the per-message ceiling is
        // `2 * max_header_list_bytes`.
        let (head_req, _) = run(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"/"),
        ])
        .expect("a small head must fit comfortably under the budget");
        assert!(head_req.headers.get_unique(b"host").is_ok());

        let mut arena4 = BytesMut::new();
        let mut trailer_full = MplexTrailerBuilder::new(&arena4, &limits, WireVersion::H2);
        // 100 fields totalling close to `max_header_list_bytes` (65,536): a fresh
        // budget accepts this even though the head above already spent one.
        // Each field costs `name (7) + value (600) + 32 == 639` bytes; 100 of
        // them cost 63,900, safely under the 65,536 ceiling.
        let value = vec![b'v'; 600];
        let mut last = Ok(());
        for i in 0..100u32 {
            let name = format!("x-t-{i:03}");
            last = trailer_full.push(&mut arena4, name.as_bytes(), &value);
        }
        assert!(
            last.is_ok(),
            "a fresh trailer budget must accept its own 100 fields"
        );

        // No method on `MplexHeadBuilder`, and none on `MplexTrailerBuilder`,
        // merges a trailer section into a header section: `MplexHeadBuilder`
        // exposes `new`, `push`, `finish` and `charged` only, and `finish`
        // consumes `self` and returns `(CanonicalRequest, TargetForm)`, never a
        // trailer-accepting variant.
    }

    const PROPTEST_NAMES: [&[u8]; 13] = [
        b":method",
        b":scheme",
        b":authority",
        b":path",
        b":protocol",
        b"host",
        b"content-length",
        b"cookie",
        b"te",
        b"connection",
        b"x-custom",
        b"X-Bad",
        b"a_b",
    ];

    fn proptest_name_strategy() -> impl proptest::strategy::Strategy<Value = &'static [u8]> {
        proptest::sample::select(&PROPTEST_NAMES[..])
    }

    fn proptest_value_strategy() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
        use proptest::prelude::*;
        prop_oneof![
            Just(b"GET".to_vec()),
            Just(b"https".to_vec()),
            Just(b"a".to_vec()),
            Just(b"/".to_vec()),
            Just(b"trailers".to_vec()),
            Just(b" bad".to_vec()),
            Just(b"bad ".to_vec()),
            Just(b"a\0b".to_vec()),
            Just(b"a\rb".to_vec()),
            Just(b"a\nb".to_vec()),
            proptest::collection::vec(any::<u8>(), 0..=8),
        ]
    }

    proptest::proptest! {
        /// Test 11 (proptest): for a generated sequence of `(name, value)` pairs
        /// drawn from an alphabet including the five pseudo-headers, six known
        /// fields, two invalid names and values containing SP, HTAB, NUL, CR and
        /// LF, `push` followed by `finish` never panics, and every `Ok` result
        /// satisfies invariant I2 (no hop-by-hop field remains).
        #[test]
        fn prop_push_never_panics(
            pairs in proptest::collection::vec(
                (proptest_name_strategy(), proptest_value_strategy()),
                0..=40,
            ),
        ) {
            let ctx = ctx();
            let mut arena = BytesMut::new();
            let mut builder = MplexHeadBuilder::new(&arena, &ctx.limits, WireVersion::H2);
            for (name, value) in &pairs {
                if builder.push(&mut arena, name, value).is_err() {
                    break;
                }
            }
            if let Ok((req, _)) = builder.finish(&ctx, &mut arena) {
                for (name, _, _) in req.headers.iter() {
                    proptest::prop_assert!(
                        !strip::is_hop_by_hop(known::classify(name)),
                        "a hop-by-hop field survived: {name:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn header_list_budget_used_keeps_growing_past_the_first_crossing() {
        // Reproduces the exact input that broke fuzz_mplex_head.rs's charged()
        // bound assertion: 100 pairs of (name = "x", value = 630 bytes), which
        // crosses the byte limit on push 99 and keeps accumulating past it.
        //
        // Calls `guarded_charged_bound` and `push_poisons_budget` rather than
        // re-deriving the same arithmetic inline: those two functions are the
        // ones `fuzz_targets/fuzz_mplex_head.rs` also calls, specifically so a
        // regression in either shared function reddens THIS test (part of
        // `cargo test`), not only a non-deterministic `cargo fuzz run`.
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = MplexHeadBuilder::new(&arena, &limits, WireVersion::H2);
        let name = b"x";
        let value = vec![b'v'; 630];

        let mut budget_poisoned = false;
        for i in 0..100u32 {
            let charged_before = builder.charged();
            let result = builder.push(&mut arena, name, &value);
            let charged_after = builder.charged();
            if budget_poisoned {
                assert!(result.is_err(), "push {i} after poisoning must fail");
            }
            if push_poisons_budget(&result, charged_before, charged_after) {
                budget_poisoned = true;
            }
            if let Some(bound) = guarded_charged_bound(
                charged_before,
                u64::from(limits.max_header_list_bytes),
                name.len(),
                value.len(),
            ) {
                assert!(
                    charged_after <= bound,
                    "guarded bound must hold at push {i}"
                );
            }
        }
        assert!(
            budget_poisoned,
            "100 pushes of 663 bytes each must cross the limit"
        );
        // The named proof that the SHIPPED, unguarded assertion was false: the
        // final charged() value exceeds what the unguarded bound would have
        // allowed for the LAST pair pushed.
        let unguarded_bound_for_last_pair = u64::from(limits.max_header_list_bytes)
            .saturating_add(name.len() as u64)
            .saturating_add(value.len() as u64)
            .saturating_add(32);
        assert!(
            builder.charged() > unguarded_bound_for_last_pair,
            "charged() = {}, unguarded bound = {unguarded_bound_for_last_pair}: \
             this must be strictly greater to prove the unguarded assertion was false",
            builder.charged()
        );
    }

    /// Establishes the claim `docs/THREAT-MODEL.md` and
    /// `fuzz_targets/fuzz_mplex_head.rs`'s module doc make: `FieldCountExceeded`
    /// has two sources, and only the header-list budget's own is terminal.
    ///
    /// Pushes `CookieAccumulator`'s `MAX_COOKIE_CRUMBS` (256) crumbs (accepted),
    /// a 257th (refused by the accumulator's own ceiling, NOT the budget), then
    /// one more, unrelated field. Ran against the poisoning logic as it shipped
    /// in this PR before this fix (treating every `FieldCountExceeded` as
    /// terminal, i.e. `matches!(result, Err(HeaderListTooLarge |
    /// FieldCountExceeded))`): the crumb-257 refusal set `budget_poisoned =
    /// true`, so the assertion on the final push panicked with "push after
    /// poisoning must fail" against an `Ok(())` result. `push_poisons_budget`
    /// below is what tells the two sources apart.
    #[test]
    fn field_count_exceeded_from_cookie_accumulator_does_not_poison_the_budget() {
        // Same limits as `cookie_crumb_flood_is_bounded`'s bound 3: a field
        // count wide enough, and a byte budget large enough, that the
        // accumulator's own 256-crumb ceiling fires before the budget's.
        let limits = Limits {
            max_field_count: 10_000,
            max_header_list_bytes: Limits::CEILING.max_header_list_bytes,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut arena = BytesMut::new();
        let mut builder = MplexHeadBuilder::new(&arena, &limits, WireVersion::H2);
        builder.push(&mut arena, b":method", b"GET").unwrap();
        builder.push(&mut arena, b":scheme", b"https").unwrap();
        builder.push(&mut arena, b":authority", b"a").unwrap();
        builder.push(&mut arena, b":path", b"/").unwrap();

        for n in 0..256u32 {
            builder
                .push(&mut arena, b"cookie", b"1")
                .unwrap_or_else(|e| panic!("crumb {n} of 256 must be accepted: {e:?}"));
        }

        let charged_before = builder.charged();
        let crumb_257 = builder.push(&mut arena, b"cookie", b"1");
        let charged_after = builder.charged();
        assert_eq!(
            crumb_257,
            Err(RejectReason::FieldCountExceeded),
            "the 257th crumb must be refused by CookieAccumulator's own ceiling"
        );
        assert!(
            !push_poisons_budget(&crumb_257, charged_before, charged_after),
            "a FieldCountExceeded from CookieAccumulator's own ceiling must not poison the budget"
        );

        // The direct, load-bearing proof: an unrelated push right after is
        // still accepted and charged. This is the exact claim
        // docs/THREAT-MODEL.md's "whole block's work is bounded by the
        // budget" paragraph and this fuzz target's module doc make.
        let charged_before_after_push = builder.charged();
        let after = builder.push(&mut arena, b"x-after", b"still-accepted");
        assert!(
            after.is_ok(),
            "a push after a cookie-only FieldCountExceeded must still succeed, got {after:?}"
        );
        assert!(
            builder.charged() > charged_before_after_push,
            "the accepted push must be charged"
        );
    }
}
