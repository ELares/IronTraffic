// SPDX-License-Identifier: MIT OR Apache-2.0
//! The allocation-ceiling gate for the `mplex::head::MplexHeadBuilder` surface.
//!
//! CORRECTED CLAIM (issue #867). This module doc previously stated, as settled
//! fact, a ceiling of two allocations for the typical head build and three for
//! the crumb-split variant. That number was never measured: the single
//! `#[test]` below is a text scan of the closed set of call sites able to
//! allocate at all, never a count of how many times the allocator was actually
//! entered. Measured directly (an out-of-tree counting `#[global_allocator]`,
//! built against this crate's own `typical_head()` and `crumb_split_head()`
//! bench inputs from `benches/http_mplex.rs`, arena reserved to 16 KiB, run
//! twice per input in the same process for determinism): the real count was 11
//! allocations for the typical head and 12 for the crumb-split variant, 5.5x
//! over the stated budget. Two small production-code changes landed alongside
//! this correction (see `MplexHeadBuilder::new`'s `scratch` reservation and the
//! `arena.reserve(256)` call early in `MplexHeadBuilder::finish`) bring the
//! same measurement to 8 and 9. That is real, verified progress, but it is
//! **not** the two-and-three ceiling this doc used to claim, and it is **not
//! enforced by any check in this repository**: see the next section for why,
//! and do not restate a two-allocation or three-allocation ceiling anywhere in
//! this file again.
//!
//! WHY NO COUNTING GATE CAN LIVE IN THIS REPOSITORY, EVEN AS A SIBLING CRATE.
//! Issue #867 designed a fix for this gap: a standalone, non-workspace-member
//! crate (`crates/irontraffic-http/alloc-verify`, an empty `[workspace]` table
//! nested manifest, the same shape `crates/irontraffic-http/fuzz/Cargo.toml`
//! already uses) that would write a real counting `#[global_allocator]` and
//! run it as a `scripts/gate.sh` step. That shape genuinely does escape a
//! `cargo clippy`/`cargo build` level lint: a nested crate with its own empty
//! `[workspace]` table is its own workspace root and does not inherit the
//! parent workspace's `[lints]`, which is exactly why `crates/irontraffic-http/fuzz/`
//! can already write the `unsafe` a libfuzzer-sys macro expands to. It does
//! **not**, however, escape `scripts/invariant-lints.sh` rule 15 (`no-unsafe`):
//! that check selects its input with `rust_files()`, which is `git ls-files -z
//! -- '*.rs'` filtered only to drop paths under `target/` or `fuzz/target/` at
//! the repository root. It has no concept of cargo workspace boundaries at
//! all, so it would scan a hypothetical `alloc-verify/src/main.rs` exactly as
//! it scans every other tracked `*.rs` file the moment that file is staged,
//! and its own failure text is explicit that there is no exception an
//! implementer may grant: "There is no exception an implementer is authorized
//! to make; raise it on the issue instead." The one mechanical escape that
//! exists, a `// it-allow: no-unsafe reason: ...` marker (already used,
//! legitimately, by the `fuzz/` targets for their libfuzzer-sys macro
//! expansion), is explicitly out of bounds for an implementer to add for this
//! purpose: this project's own coder contract calls that exact move
//! "self-granted" and refuses it, because an implementer who can silence the
//! one rule blocking a counting allocator could always make any allocation
//! claim true by definition. So: `GlobalAlloc` is an `unsafe trait`, and a
//! counting `#[global_allocator]` cannot live anywhere in this repository, not
//! only inside this package; a process-wide one would in any case count
//! allocations made by every other test running in parallel in the same
//! binary. The full argument for the text-scan alternative is in
//! `tests/alloc_gate_common/mod.rs`. The 8/9 figures above come from a
//! throwaway crate built OUTSIDE this repository (never committed, so it
//! cannot rot into a second false "settled fact"): treat them as a one-time
//! data point from this change's own investigation, not a continuously
//! enforced invariant, and re-measure the same way before trusting them again
//! after a further change to `MplexHeadBuilder`, `FieldSectionBuilder`,
//! `NormalizedPath::parse_into`, `reconcile_authority` or
//! `ForwardedChain::from_section`.
//!
//! WHAT THIS GATE PROVES, AND WHAT IT DOES NOT. Every other `alloc_gate_*.rs`
//! file in this crate proves a ZERO-allocation claim: the scanned function's own
//! text contains none of `ALLOCATING_CALLS`. This surface is different: the
//! design deliberately allocates a bounded, small, NON-zero number of times
//! (`scratch`'s own first growth, the field section's `split_off`, and, only
//! for the crumb-split variant, one join buffer), and names each one. What a
//! text scan CAN still prove, exhaustively, is the closed INVENTORY of call
//! sites able to grow the heap at all: this file asserts that
//! `MplexHeadBuilder::push`'s own body contains no call from the general
//! `ALLOCATING_CALLS` vocabulary (`Vec::new()`, `String::from(..)`, `.clone()`
//! and the rest) and exactly the two `self.scratch.extend_from_slice(` sites the
//! design names (one for a pseudo-header value, one for a `cookie` crumb, both
//! writing into the SAME `scratch` buffer, so only the first one to actually run
//! out of capacity allocates); that `MplexHeadBuilder::finish`'s own body
//! contains no call from the general vocabulary either, and exactly one
//! `BytesMut::with_capacity(` site, reached only on the crumb-split (two or
//! more crumbs) branch of the `cookie` join. The `arena`-side allocation the
//! design attributes to "the field section's `split_off`" is inside
//! `FieldSectionBuilder::finish`, a callee this file does not re-scan, exactly
//! as `tests/alloc_gate_h1_canonicalize.rs` already treats it as a separate
//! surface with its own accounting.
//!
//! This is therefore a STATIC proof that the call-site inventory matches the
//! design's own accounting, not a runtime-verified count of how many times the
//! allocator was actually entered: verifying the runtime count would need a
//! counting `#[global_allocator]`, which is unsound here and which this
//! project's own coder contract explicitly forbids writing. A regression that
//! adds a third `self.scratch.extend_from_slice(` call, a second
//! `BytesMut::with_capacity(`, or any call from the general vocabulary to
//! either function is exactly the shape of bug this file exists to catch: "a
//! higher count means a `Vec`, a `String` or the pseudo-header values wrongly
//! routed through the arena," in the issue's own words.

mod alloc_gate_common;

use alloc_gate_common::{ALLOCATING_CALLS, extract_fn_body};

#[test]
fn head_builder_allocation_call_sites_match_the_design() {
    let source = include_str!("../src/mplex/head.rs");

    let push_body = extract_fn_body(
        source,
        "pub fn push(\n        &mut self,\n        arena: &mut BytesMut,\n        name: &[u8],\n        value: &[u8],\n    ) -> Result<(), RejectReason> {",
    )
    .expect("`MplexHeadBuilder::push` not found in src/mplex/head.rs; has it moved or been renamed?");

    let finish_body = extract_fn_body(
        source,
        "pub fn finish(\n        mut self,\n        ctx: &MplexContext<'_>,\n        arena: &mut BytesMut,\n    ) -> Result<(CanonicalRequest, TargetForm), RejectReason> {",
    )
    .expect("`MplexHeadBuilder::finish` not found in src/mplex/head.rs; has it moved or been renamed?");

    for call in ALLOCATING_CALLS {
        assert!(
            !push_body.contains(call),
            "MplexHeadBuilder::push's body contains `{call}`, which can allocate; \
             the only allocating operation this function may perform is growing \
             `scratch`, which is charged against the header-list budget"
        );
        assert!(
            !finish_body.contains(call),
            "MplexHeadBuilder::finish's body contains `{call}`, which can allocate \
             outside the two named, bounded sites this gate tracks explicitly \
             (the cookie join buffer and the field section's own split_off, the \
             latter inside a callee this file does not re-scan)"
        );
    }

    // `push`: exactly two sites write into `scratch` (a pseudo-header value, and
    // a `cookie` crumb), both quoting the exact call this design names as
    // "the scratch buffer's first growth". A third site would mean a third kind
    // of value routed through `scratch`, which the design does not authorize.
    let scratch_growth_sites = push_body.matches("self.scratch.extend_from_slice(").count();
    assert_eq!(
        scratch_growth_sites, 2,
        "MplexHeadBuilder::push must grow `scratch` from exactly two call sites \
         (a pseudo-header value and a cookie crumb); found {scratch_growth_sites}"
    );

    // `finish`: exactly one `BytesMut::with_capacity(` site, the crumb-split
    // join buffer, reached only when there are two or more cookie crumbs. The
    // single-crumb and no-crumb branches read `scratch` directly and allocate
    // nothing of their own.
    let join_buffer_sites = finish_body.matches("BytesMut::with_capacity(").count();
    assert_eq!(
        join_buffer_sites, 1,
        "MplexHeadBuilder::finish must construct the cookie join buffer from \
         exactly one call site, reached only on the crumb-split branch; found \
         {join_buffer_sites}"
    );
}
