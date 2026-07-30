# Release engineering

Reproducibility is the foundation the rest of release engineering stands on: a signature over an
artifact nobody can rebuild proves only that we signed something, and a software bill of materials
for a binary nobody can reproduce is a claim about a build we cannot re-examine. This document is
the release matrix, the reproducibility recipe, and the support statement; scripts/release/ is the
recipe itself, and it is meant to be read alongside this file, not instead of it.

## Toolchain

`rust-toolchain.toml` pins an exact rustc version, currently `1.97.0`, never `stable`. A different
rustc emits different bytes for the identical source, so two builds under a moving channel would
never match no matter how carefully every other source of nondeterminism below is controlled.
Bumping the pin is a reviewed change that invalidates every prior release artifact by construction;
that is the intended, honest behavior, and `scripts/release/verify-repro.sh` fails naming the
toolchain if the two builds it compares ever used different ones.

## The release matrix

| Target | Linkage | Notes |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | dynamic glibc | the default for most distributions |
| `aarch64-unknown-linux-gnu` | dynamic glibc | |
| `x86_64-unknown-linux-musl` | fully static | |
| `aarch64-unknown-linux-musl` | fully static | |

Plus one non-shipped matrix entry, built and tested on every pull request rather than only at
release: `x86_64-unknown-linux-gnu` with `--no-default-features`. It is never published; its purpose
is proving the data-plane-only, control-plane-free build (`--features dataplane`) does not rot, the
same property the `dataplane-build` job in `.github/workflows/ci.yml` already checks on every pull
request.

**What this table does not yet say, said plainly.** The design this issue was written against
assumes `crates/irontraffic` already selects a TLS crypto provider (an `aws-lc-rs` default and a
`ring-provider` fallback feature, mirroring `crates/irontraffic-tls`'s three `crypto-*` features) and
therefore assumes the musl targets' cleanliness depends on `aws-lc-sys` having pre-generated bindings
for exactly those two architectures. As of this document, `crates/irontraffic` (the release binary)
does not depend on `crates/irontraffic-tls` at all: it has no crypto provider selection, no `tls` or
`zstd` Cargo feature, and no `ring-provider` fallback feature, so today's release binary carries no
TLS support of any kind. Its two real features are `control-plane` (default) and `dataplane`. This
means:

- The four targets above build cleanly today for a much simpler reason than the aws-lc-sys binding
  story: there is currently no C dependency in this binary's graph at all, on any target.
- The "everything else builds with `ring-provider`, best effort, no FIPS" fallback-matrix entry this
  design calls for cannot be added to `.github/workflows/ci.yml` as a real, exercised CI job, because
  the feature it would build does not exist on this crate. Adding a CI step that passes
  `--features ring-provider` to a crate with no such feature would fail every run, and inventing an
  inert placeholder feature that toggles nothing would be exactly the kind of untested "we have a
  fallback" claim `{{release-reproducible-build-and-artifacts}}`'s own Context section warns against.
- `crates/irontraffic-tls`'s three mutually exclusive `crypto-*` providers, its `crypto-fips`
  artifact, and the `deny.toml` OpenSSL licence exception for `aws-lc-fips-sys` (issue #488) are real
  and already shipped, but they describe `crates/irontraffic-tls` in isolation, checked by its own
  crate-level `feature-matrix` CI job. None of it is reachable yet from the `irontraffic` binary this
  release recipe packages.
- When a future issue wires TLS into `crates/irontraffic` (giving it real `tls`/`zstd`/`ring-provider`
  features), this document, the CI matrix, and `NOTICE` all need a follow-up pass: the ring-provider
  fallback entry described above, the `crypto-fips` NOTICE section, and the musl-cleanliness reasoning
  in the aws-lc-sys sense all become applicable at that point and not before.

Windows is a v1 non-goal: no target in the matrix above ends in `-pc-windows-*`, and none is planned.
macOS is a development platform only: it is where this project's contributors run `cargo build`
day to day, but it is not a release target, and this workspace's own CI never builds a macOS binary.

## The deterministic build recipe

`scripts/release/build.sh <target>` sets exactly this environment and nothing else, then runs one
`cargo build --locked --release`:

- `SOURCE_DATE_EPOCH`, from the tag's commit date (`git log -1 --pretty=%ct`), so any embedded
  timestamp is derived rather than sampled. If git is unavailable, it falls back to `0` (the Unix
  epoch) with a warning: a fixed wrong timestamp is still reproducible, and a sampled one is not.
- `IT_GIT_SHA` and `IT_GIT_DIRTY`, from `git rev-parse --short=12 HEAD` and `git status --porcelain`,
  passed to `crates/irontraffic/build.rs` as environment variables rather than left for it to derive
  independently, which is what makes a build from a source tarball with no `.git` directory
  reproducible: the binary depends on the environment, never on the presence of a `.git` directory.
- `CARGO_PROFILE_RELEASE_DEBUG=0` and `CARGO_PROFILE_RELEASE_STRIP=symbols`, so debug information and
  the symbol table (the two largest carriers of path and timestamp residue) are absent from the
  release artifact. Debug information for profiling is a separate, non-release build; this script
  never produces one.
- `CARGO_PROFILE_RELEASE_LTO=thin` and `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`. The codegen-units
  setting is required for reproducibility, not speed: with more than one unit, the partition of
  functions across units depends on a hash whose interaction with incremental state is not stable
  across otherwise-identical builds, and the practical effect is occasional byte differences. It also
  happens to produce better code, which is why it is a defensible release-only setting.
- `RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"`,
  so absolute source and registry paths never enter the binary. This is the single largest lever on
  reproducibility across two different checkouts: measured locally (see "What was actually verified"
  below), disabling it while leaving debug information on made two otherwise identical builds at two
  different absolute paths diverge; restoring it made them match again.

`scripts/release/build.sh` refuses to run on a dirty worktree (or one whose cleanliness could not be
determined at all, which is treated the same, unsafe direction as dirty) unless `IT_ALLOW_DIRTY=1`,
in which case it stamps `dirty: true`, which every downstream consumer treats as unreleasable.

## `scripts/release/verify-repro.sh`

Builds one target twice, at two different absolute paths (a real copy of the tracked tree, including
`.git`, so `git`-derived values come out identically at both), and compares the resulting binaries
byte for byte. A verification that builds twice in the *same* directory proves almost nothing: it is
the different absolute path that actually exercises `--remap-path-prefix`. It also compares
`rustc -vV` between the two builds and fails naming the toolchain if they differ, because a toolchain
difference is the second most common cause of a mismatch, after a path leak.

On a mismatch it prints the first 32 differing byte offsets (`cmp -l`) and, where `readelf` is
available, both binaries' `.comment` section, because the overwhelmingly common cause of a genuine
mismatch is a path or a compiler version leaking in.

## `scripts/release/build-matrix.sh`

Drives `build.sh` across the four shipped targets and assembles, per target:

```
irontraffic-<version>-<target>.tar.gz
  irontraffic-<version>-<target>/
    irontraffic
    LICENSE
    README.md
    docs/QUICKSTART.md
SHA256SUMS          # one line per tarball, plain sha256sum format
```

with a fixed member order (sorted), fixed ownership (`0`/`0`), fixed permissions (`0755` for the
binary, `0644` otherwise), and `SOURCE_DATE_EPOCH` as every member's mtime, including the gzip
container's own timestamp header: `tar`'s and `gzip`'s own defaults would otherwise make an
otherwise-reproducible binary land in an irreproducible archive, or (the gzip header's `FNAME` field)
carry the output path's basename into the compressed bytes.

## What `SHA256SUMS` proves, and what it does not

`SHA256SUMS` is fetched from the same origin as the tarball it accompanies. Anyone who can serve a
modified tarball can serve a matching `SHA256SUMS`, so it proves the transfer was not corrupted and
proves nothing about who produced the artifact. `scripts/install.sh` prints exactly that sentence,
`checksum verified (integrity only; signature verification lands in the next release)`, rather than
the word "verified" alone, and `docs/THREAT-MODEL.md` records the same thing. Signature verification
arrives with `{{release-sbom-signing-and-provenance}}` and becomes the default there.

## Installing

```sh
curl -fsSL https://github.com/ELares/IronTraffic/releases/latest/download/install.sh | sh
```

detects the platform, refuses anything outside the four-target matrix by name, downloads the tarball
and `SHA256SUMS` over TLS 1.2+, verifies the checksum, runs the extracted binary's `--version` before
moving anything into place, and installs to `$HOME/.local/bin` by default (`--prefix` to override).
It refuses to run as root unless `IT_ALLOW_ROOT=1`. See `scripts/install.sh --help`.

## What was actually verified, and how

This workspace's release build has not yet run on the real four-target CI matrix (that lane is added
by this same change but has not executed yet), and this repository was implemented and verified from
a macOS development machine with no Docker or Linux cross-toolchain available, which the "macOS is a
development platform only" line above exists to say plainly rather than leave a reader to infer.
Concretely, that means:

- The **mechanism** (`--remap-path-prefix` plus the environment-derived version stamp plus the
  profile overrides) was verified end to end for `x86_64-unknown-linux-musl`: two builds of the
  identical commit, at two different absolute paths, two different `--target-dir` locations, and two
  different `TMPDIR` values, produced byte-for-byte identical binaries. A negative control (the
  identical two builds with `--remap-path-prefix` removed and debug information turned back on)
  produced two *different* binaries, which is what proves the flag is load-bearing rather than
  incidental.
- Linking a `x86_64-unknown-linux-musl` or any `-gnu` target from macOS needs either a real cross
  toolchain or Docker, neither present in that environment; the verification above therefore used
  `rustc`'s bundled `rust-lld` invoked directly (a linker override outside `scripts/release/build.sh`
  itself, which does not and should not carry a macOS-specific linker workaround, since its real
  target environment is the Ubuntu CI runner where the system `cc`, or `musl-tools`' `musl-gcc`,
  links these targets without any such override).
- `scripts/release/verify-repro.sh` itself was run for real against `x86_64-unknown-linux-musl` on
  that same machine and failed at exactly the expected point (the plain `cc` link step, for the
  identical missing-cross-linker reason above), which exercises everything around that step (the
  second-path copy, the dirty-tree gate, the toolchain comparison) without being able to reach a
  green result on this machine.
- `scripts/install.sh` was verified end to end against a local HTTPS server serving a real tarball
  built by `scripts/release/build-matrix.sh`'s own assembly logic (with a stand-in executable in
  place of the real ELF binary, which this same macOS machine cannot run): version resolution,
  checksum verification (including a deliberately corrupted artifact, which was correctly refused),
  the root refusal and its override, atomic install with a `.previous` backup, `umask` independence
  under both `077` and `000`, truncated-download safety at five different truncation points, rejection
  of three different malicious `IT_VERSION` values, and cleanup on an interrupting `SIGINT` all passed.
- `scripts/release/release-selftest.sh` (the fifteen script tests this issue's own Tests section
  describes; see its own header comment for why it exists but is not in the Files table) runs and
  passes all fourteen of its checks when the host is made to report itself as Linux (this
  development machine's real `uname` reports macOS, which `scripts/install.sh` correctly refuses, by
  design, before any of those checks would otherwise run). Run as written, with no such override, on
  this development machine, 3 of the 14 checks pass anyway (the ones whose assertion happens to hold
  regardless of the host OS) and the rest fail loudly, for the one, understood, and reported reason:
  `scripts/install.sh` refuses a non-Linux host. On the real `shell-selftests` CI runner (Ubuntu),
  no override is needed at all.
- The `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`, and `x86_64-unknown-linux-gnu`
  targets, the real four-tarball `build-matrix.sh` run against genuine ELF binaries, `ldd`'s actual
  verdict on those binaries, and the `aarch64-linux-musl-cross` toolchain download in the
  `release-artifacts` job were **not** run end to end anywhere in this change's verification; none of
  them can be, from this machine. They are exercised by the `release-artifacts` CI job this change
  adds, which does run on Ubuntu with the correct cross toolchains installed, and its first real run
  is the first genuine test of the `aarch64-linux-musl-cross` download step specifically.
