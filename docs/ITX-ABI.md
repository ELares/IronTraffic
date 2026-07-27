# ITX ABI v1

This document is the guest-facing contract for IronTraffic's core-module
WebAssembly ABI, version 1. It is intentionally independent of any host runtime:
everything here is a wire format, a bounds-checking primitive, or a pure
function over a byte slice.

ITX is a core-module ABI, not a component-model ABI. The migration gate is at
the end of this document.

## Why not proxy-wasm

proxy-wasm is documented, feature-gated compatibility shim material, not the
native ABI, for four reasons:

1. **Caller-allocates transfer.** proxy-wasm's `abi-versions/README.md` says the
   host must call back into the guest allocator (`proxy_on_memory_allocate`) for
   every piece of memory-managed data. ITX uses the `readlink(2)` convention:
   the guest passes `out_ptr` and `out_cap`; the host fills the buffer and
   returns the length, or a negative needed length when the buffer was too
   small. There is no re-entrant allocation callback.
2. **Guest-declared phases.** A proxy-wasm host has no cheap way to know which
   phases a guest subscribes to. ITX derives the phase mask from the exports the
   module actually defines, checked once at load time.
3. **No string-path property access.** proxy-wasm's `proxy_get_property` takes a
   serialized string path into host state. ITX has `itx_get_attr(attr_id, ...)`,
   where `attr_id` is a numeric id from the same closed schema that ITPL uses.
4. **Governance.** The proxy-wasm specification repository has been effectively
   abandoned, and at least one vendor shipped a proxy-wasm host and then removed
   it. Owning the ABI keeps the gate in our own tree.

## Exports

Every export is `extern "C"`, takes and returns `i32` only, and is optional
except the first two. The host derives the phase mask from which per-stream
exports are present.

| export | signature | meaning |
| --- | --- | --- |
| `itx_abi_version` | `() -> i32` | must return 1; anything else fails load |
| `itx_on_config` | `(ptr: i32, len: i32) -> i32` | once per instance; host wrote the config blob at `ptr` |
| `itx_on_stream_start` | `(ctx: i32) -> i32` | |
| `itx_on_request_headers` | `(ctx: i32) -> i32` | |
| `itx_on_request_body` | `(ctx: i32, end_of_stream: i32) -> i32` | |
| `itx_on_request_trailers` | `(ctx: i32) -> i32` | |
| `itx_on_response_headers` | `(ctx: i32) -> i32` | |
| `itx_on_response_body` | `(ctx: i32, end_of_stream: i32) -> i32` | |
| `itx_on_response_trailers` | `(ctx: i32) -> i32` | |
| `itx_on_stream_destroy` | `(ctx: i32)` | must not fail; return value ignored |

`itx_on_stream_destroy` is required whenever any per-stream export is defined.

## Imports

All imports live in the module namespace `itx` and are caller-allocates: the
guest provides the destination pointer and capacity, and the host returns the
number of bytes written, a negative needed length, or an error code.

| import | signature |
| --- | --- |
| `itx_get_header` | `(name_ptr, name_len, out_ptr, out_cap) -> i32` |
| `itx_header_count` | `() -> i32` |
| `itx_get_header_at` | `(idx, out_ptr, out_cap) -> i32` |
| `itx_set_header` | `(name_ptr, name_len, val_ptr, val_len) -> i32` |
| `itx_remove_header` | `(name_ptr, name_len) -> i32` |
| `itx_apply_ops` | `(ptr, len) -> i32` |
| `itx_get_attr` | `(attr_id, out_ptr, out_cap) -> i32` |
| `itx_body_len` | `() -> i32` |
| `itx_body_read` | `(off, out_ptr, out_cap) -> i32` |
| `itx_body_replace` | `(ptr, len) -> i32` |
| `itx_log` | `(level, ptr, len)` |

### Reserved imports

`itx_call_service` and `itx_call_result` are reserved names in v1. The host does
not define them, and a module that imports either fails to load with a named
error. They are reserved while the outbound-call design, which needs upstream
connection pools, lands in a later milestone.

## Return encoding

A guest phase export returns a single `i32`. Negative values are guest-reported
failures. Non-negative values encode one of four actions.

| action | low nibble | payload |
| --- | --- | --- |
| `Continue` | 0 | bits 4..29 must be 0 |
| `Pause` | 1 | bits 4..29 must be 0 |
| `Respond` | 2 | bits 4..13 hold `status - 100`; bits 14..29 hold the template index, where `65535` means no template |
| `Reset` | 3 | bits 4..5 hold the reset code; bits 6..29 must be 0 |
| undefined | 4..15 | `UnknownAction` |

Bits 30 and 31 must be 0 on every non-negative return value. This leaves the
full negative range for guest errors and guarantees that every payload field
fits in 30 bits.

`Respond` rejects any decoded status outside `200..=599`. The field layout uses
a bias of 100 so that a 1xx direct response is representable in the encoding but
explicitly rejected at decode: a filter-generated 1xx would leave the
downstream peer waiting for a final response that never arrives.

## `guest_slice`

`guest_slice(mem, ptr, len)` is the single function that turns a guest `(ptr,
len)` pair into a Rust slice. It performs the addition in `u64` so that
`ptr = 0xFFFFFFF0` and `len = 0x20` overflow rather than passing a length check
against `mem.len()`. The mutable twin, `guest_slice_mut`, is identical and is
used only by host functions that fill a guest-provided buffer.

## Op-list wire format

`itx_apply_ops` receives a batched list of header mutations. Each record is 20
bytes, 4-byte aligned, little-endian:

| offset | type | field |
| --- | --- | --- |
| 0 | u8 | `op`: 0 `Append`, 1 `Set`, 2 `Remove` |
| 1 | u8 | `target`: 0 for the header section of the current phase; other values are reserved |
| 2 | u16 | `reserved`: must be 0 |
| 4 | u32 | `name_ptr` |
| 8 | u32 | `name_len` |
| 12 | u32 | `value_ptr`: 0 for `Remove` |
| 16 | u32 | `value_len`: 0 for `Remove` |

`name_len` and, for non-`Remove` ops, `value_len` may not exceed
`MAX_OP_FIELD_BYTES` (65,536). Names and values may overlap each other or the
op list itself; the host only reads. The decoder yields an iterator over
borrowed `(op, name, value)` triples so the host can push directly into the
chain's op ledger without an intermediate collection.

## Component-model migration gate

ITX v1 is a core-module ABI because, on the same host and toolchain generation,
a warm core-module export call costs about 10 to 11 nanoseconds while a
component-model warm export call costs about 260 to 264 nanoseconds. At four
phases per request per filter, that is roughly one microsecond of pure ABI tax.

IronTraffic will move to WIT-defined component interfaces when either of the
following is true:

- A component export call, measured by the same benchmark on the same class of
  hardware, costs under 30 nanoseconds; or
- Composition of third-party modules gives us something we cannot otherwise get.

Until then, the core-module ABI is the native path and the component model is a
future option behind this explicit gate.
