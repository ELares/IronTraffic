# TLS crypto provider build matrix

`crates/irontraffic-tls` pins rustls 0.23.42 and offers exactly three mutually exclusive crypto
provider features: `crypto-aws-lc-rs` (default), `crypto-ring`, and `crypto-fips`. This document
states which provider each shipping target builds with, what each build gains and loses, and how a
failure to install that provider must be handled at startup.

## Shipping target matrix

The release matrix is `{x86_64, aarch64} x {gnu, musl}` on aws-lc-rs. Every other target builds with
`crypto-ring`, best effort, no FIPS, no post-quantum key exchange.

| Target | Provider feature | FIPS available | Post-quantum key exchange | cmake + C/C++ compiler required |
| --- | --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `crypto-aws-lc-rs` (or `crypto-fips` as a separate artifact) | yes, as a separate `crypto-fips` artifact | yes (X25519MLKEM768) | yes |
| `x86_64-unknown-linux-musl` | `crypto-aws-lc-rs` (or `crypto-fips` as a separate artifact) | yes, as a separate `crypto-fips` artifact | yes (X25519MLKEM768) | no; `aws-lc-sys` ships pre-generated bindings for this target |
| `aarch64-unknown-linux-gnu` | `crypto-aws-lc-rs` (or `crypto-fips` as a separate artifact) | yes, as a separate `crypto-fips` artifact | yes (X25519MLKEM768) | yes |
| `aarch64-unknown-linux-musl` | `crypto-aws-lc-rs` (or `crypto-fips` as a separate artifact) | yes, as a separate `crypto-fips` artifact | yes (X25519MLKEM768) | no; `aws-lc-sys` ships pre-generated bindings for this target |
| everything else | `crypto-ring` | no | no; `ring` has no ML-KEM | no |

Notes on the table:

- FIPS is never a runtime flag. It changes which key exchange groups rustls compiles in (plain
  X25519 is compiled out of `DEFAULT_KX_GROUPS` under the `fips` feature, while the hybrid
  X25519MLKEM768 stays in), so a FIPS binary is a distinct build artifact selected with
  `--no-default-features --features crypto-fips`, never a configuration value read at startup.
- `crypto-aws-lc-rs` and `crypto-fips` both build on `rustls::crypto::aws_lc_rs`; the `fips`
  Cargo feature changes what the resulting `CryptoProvider` value contains, not which constructor
  is called.
- `crypto-ring` never offers post-quantum hybrid key exchange, because `ring` has no ML-KEM
  implementation, independent of any caller preference.
- Exotic musl targets outside this table (mips musl, riscv64 musl, some Android cross setups) do
  not have pre-generated `aws-lc-sys` bindings and fall into the "everything else" row: build with
  `crypto-ring` and accept the loss of FIPS and post-quantum key exchange, or supply `bindgen` and a
  cmake plus C/C++ toolchain for the target and build `crypto-aws-lc-rs` best effort.

## `--all-features` cannot build this crate

`crates/irontraffic-tls`'s three `crypto-*` features are mutually exclusive by design: enabling more
than one is a compile error, because a process may not decide its cipher policy and its FIPS answer
in two places at once. `cargo build --all-features` (and `cargo clippy` or `cargo test` with the same
flag) therefore fails to compile this crate, on purpose, with the message:

```
irontraffic-tls crypto provider features are mutually exclusive: pick exactly one
```

A CI job that runs `--all-features` across the workspace must exclude this crate's provider
features rather than treat the failure as a defect. The root `Cargo.toml` `[workspace.dependencies]`
entry for `rustls` carries a comment recording this, next to the entry itself.

## Startup failure handling

`install_process_provider()` can return two errors, and both are fatal startup errors: the caller
MUST abort the process and MUST NOT build any `ServerConfig` or `ClientConfig` after seeing either
one.

- **`ProviderError::AlreadyInstalled`**: a crypto provider was already installed in this process,
  by either a second call to `install_process_provider()` or another subsystem installing one
  first. The two cases are indistinguishable and handled the same way. The provider that is
  actually active was not chosen by this call, so nothing downstream may assume it matches the
  build's intended policy.
- **`ProviderError::FipsNotActive`**: this is a `crypto-fips` build, but the installed provider
  reports `fips() == false`. This carries a sharper hazard than the name alone suggests: by the
  time this error is returned, `rustls::crypto::CryptoProvider::install_default` has **already
  succeeded**, so a non-FIPS provider is already installed process-wide, and rustls offers no way to
  uninstall it. `crates/irontraffic-tls` cannot undo the installation from inside this call.
  Treating this error as a warning and continuing ships a binary that claims FIPS compliance while
  running a provider that is not in FIPS mode, which is the exact fail-open outcome this check
  exists to prevent. The only correct response is for the caller to abort the process immediately,
  before any listener accepts a connection.

`crates/irontraffic-tls` itself never calls `panic!` or `std::process::exit` for either case; it
returns the `Result` and leaves the abort decision to the binary that called
`install_process_provider()` during startup.
