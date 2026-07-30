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
    LICENSE-APACHE
    LICENSE-MIT
    NOTICE
    README.md
    docs/QUICKSTART.md
SHA256SUMS          # one line per tarball, plain sha256sum format
```

`LICENSE` is a two-option pointer file (Apache-2.0 or MIT, at the reader's choice) that names
`LICENSE-APACHE` and `LICENSE-MIT` by path; both are shipped alongside it so the reference resolves
offline, inside the archive itself, rather than sending a reader to the repository to find the text
`LICENSE` points at. `NOTICE` is the third-party attribution file the FIPS artifact's OpenSSL licence
exception (issue #488) requires; it is packaged into every tarball, not only a `crypto-fips` one,
because the release binary this issue packages does not yet select a feature set narrow enough to
omit it (see "What this table does not yet say" above).

with a fixed member order (sorted), fixed ownership (`0`/`0`), fixed permissions (`0755` for the
binary, `0644` otherwise), and `SOURCE_DATE_EPOCH` as every member's mtime, including the gzip
container's own timestamp header: `tar`'s and `gzip`'s own defaults would otherwise make an
otherwise-reproducible binary land in an irreproducible archive, or (the gzip header's `FNAME` field)
carry the output path's basename into the compressed bytes.

## What `SHA256SUMS` proves, and what it does not

`SHA256SUMS` is fetched from the same origin as the tarball it accompanies. Anyone who can serve a
modified tarball can serve a matching `SHA256SUMS`, so it proves the transfer was not corrupted and
proves nothing about who produced the artifact. `scripts/install.sh` prints exactly that sentence,
`checksum verified (integrity only)`, rather than the word "verified" alone, and
`docs/THREAT-MODEL.md` records the same thing. What closes the provenance gap is the signature and
build provenance attestation `docs/SUPPLY-CHAIN.md` documents in full: a CycloneDX SBOM per artifact,
a keyless `cosign` signature over every published file, an in-toto attestation naming the source
commit and builder, and `scripts/release/verify.sh`, which `scripts/install.sh` now runs by default
before installing anything.

## Installing

```sh
curl -fsSL https://github.com/ELares/IronTraffic/releases/latest/download/install.sh | sh
```

detects the platform, refuses anything outside the four-target matrix by name, downloads the tarball
and `SHA256SUMS` over TLS 1.2+, verifies the checksum, downloads and runs `scripts/release/verify.sh
--strict` (signature and build provenance, on by default; see `docs/SUPPLY-CHAIN.md`), runs the
extracted binary's `--version` before moving anything into place, and installs to `$HOME/.local/bin`
by default (`--prefix` to override). It refuses to run as root unless `IT_ALLOW_ROOT=1`, and refuses
to install at all if signature verification fails or could not be performed, unless the explicit,
warned `--no-verify-signature` opt-out is passed. See `scripts/install.sh --help`.

## Rebuilding and comparing

A signature and a provenance attestation say this project produced an artifact from a stated commit;
they do not, by themselves, say that commit produces the artifact. `scripts/release/verify-repro.sh`
is the complementary, stronger check:

```sh
git checkout <commit named by verify.sh>
sh scripts/release/verify-repro.sh <target>
```

It builds the named commit twice, at two different absolute paths, and asserts the two binaries are
byte-for-byte identical, closing the loop from "we said we built this" to "anyone can rebuild this and
get the same bytes." See `docs/SUPPLY-CHAIN.md` section 4 for the full command sequence starting from
a downloaded artifact.

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
  `scripts/install.sh` refuses a non-Linux host.
- The `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`, and `x86_64-unknown-linux-gnu`
  targets, the real four-tarball `build-matrix.sh` run against genuine ELF binaries, `ldd`'s actual
  verdict on those binaries, and the `aarch64-linux-musl-cross` toolchain download in the
  `release-artifacts` job were **not** run end to end anywhere in this change's verification; none of
  them can be, from this machine. They are exercised by the `release-artifacts` CI job this change
  adds, which does run on Ubuntu with the correct cross toolchains installed, and its first real run
  is the first genuine test of the `aarch64-linux-musl-cross` download step specifically.

## What the first real Ubuntu CI run found, and what this fix round changed

The paragraph above described what a macOS machine with no Docker or Linux cross-toolchain could
verify before this repository's `shell-selftests` job had ever run for real. It has now run, on the
real Ubuntu CI runner, and an independent adversarial review reproduced the reproducibility claim
directly (at two absolute paths of *different* lengths, with different target directories and
`TMPDIR`s, both the positive and negative control held) while tracing everything the macOS-only
verification above could not reach. That review is the source of the four fixes below; each was
watched to fail before being trusted, on this same macOS development machine, using the specific
technique named:

- **The mode probe (`install_sets_mode_regardless_of_umask`) could never pass on real Ubuntu CI.**
  `release-selftest.sh` measured the installed mode with `stat -f '%Lp' FILE 2>/dev/null || stat -c
  '%a' FILE 2>/dev/null`: the `-f` form is BSD/macOS's format flag, but under GNU coreutils `-f` means
  `--file-system` and `%L` is an unrecognized directive there, which coreutils prints as a literal `?`
  **without** setting a failure flag, so the command exits 0 with garbage output and the `||`
  fallback never runs. This was the actual, reported cause of a 13/14 result on the real CI runner.
  Fixed by trying `stat -c '%a'` first (GNU's form; it errors outright on BSD, correctly falling
  through) and rejecting any reading that is not exactly three octal digits, rather than trusting a
  coincidental string mismatch against `"755"` to mean "wrong mode". Verified on this macOS machine
  two ways: (1) the real, unmodified fix, run for real, produces `14/14`; (2) a `stat` stub was built
  that reproduces GNU coreutils' documented behavior exactly (`-c` returns the real mode via a direct
  `stat()` syscall read; `-f` prints `?p` and exits 0), and against that stub the *old* probe order
  reported `FAIL` on a file that genuinely was `0755`, while the *new* order correctly reported
  `PASS`. This is the closest a macOS machine can get to reproducing the GNU-specific defect without
  a Linux host, and it is not the same as having run it on one.
- **`install_refuses_root` was vacuous.** The no-`IT_ALLOW_ROOT` arm never pointed at the local
  fixture server, so with the entire root-refusal block deleted, execution simply proceeded past the
  missing check into `resolve_latest_version` against the real `github.com` and failed for an
  unrelated reason, still satisfying `[ "$status" -ne 0 ]`. Fixed by pointing that arm at the fixture
  too and asserting the exact refusal message. Watched to fail: with the root-refusal block replaced
  by `:`, the fixed test correctly reports `FAIL`; reverted, it is back to `14/14`.
- **`install_cleans_up_on_interrupt` never entered `main` and never checked for a surviving temp
  directory.** The injected delay ran *before* `main "$@"`, so `SIGINT` landed during a bare `sleep`
  with no temp directory ever created; the assertion (`no binary was installed`) was trivially true
  regardless of whether cleanup does anything at all, and the second half of the test the issue's own
  edge case names (no temp directory survives) was never checked. Fixed by moving the delay inside
  the real download path (the fixture server sleeps before answering the tarball request specifically,
  while a marker file exists) and delivering `SIGINT` to the whole process group, not `install.sh`'s
  own PID alone: verified directly, with a `sleep` standing in for `curl`, that signalling only the
  parent process leaves a synchronous foreground child running to completion and defers a trap on
  `INT` until that child exits on its own, which is indistinguishable, at the timescale this test
  checks on, from the trap never running. `mktemp -d`'s own directory is also redirected, via a PATH stub, into a
  directory this test controls: plain `$TMPDIR` was tried first and found unreliable for this
  specifically on macOS (BSD `mktemp -d` with no template ignores an exported `$TMPDIR` in favor of
  `_CS_DARWIN_USER_TEMP_DIR`, verified directly), which would have made the leftover-directory check
  silently vacuous on this development machine while remaining meaningful on Linux; the stub sidesteps
  that platform difference entirely rather than relying on it. Watched to fail: with the cleanup
  `trap` replaced by `:`, the fixed test correctly reports `FAIL - install_cleans_up_on_interrupt`
  with the diagnostic `a temporary directory survived under FORCE_MKTEMP_DIR: tmp.<random>`; reverted,
  `14/14` again.
- **The tag-triggered `release-artifacts` job could not have succeeded even once.**
  `build-matrix.sh` created its output directory (`dist/`, not then in `.gitignore`) and wrote
  `SHA256SUMS` into it *before* the first target's `build.sh` call, so on a pristine tag checkout
  `git status --porcelain` reported `?? dist/` starting with target 1 of 4, and `build.sh`'s own dirty
  gate refused every single target for the rest of the run. Fixed by staging every tarball and the
  checksum manifest in a `mktemp -d` *outside* the repository tree, and copying the finished artifacts
  into the real output directory only after every target has built (`/dist` was also added to
  `.gitignore`, for a stale directory left over from a previous local run). Verified on this machine
  with a harness that reproduces the actual bug and the actual fix without needing cross-compilation:
  a real git repository, the real, unmodified `build.sh` and `build-matrix.sh`, and a stand-in `cargo`
  that answers `cargo metadata` and creates a placeholder file instead of compiling anything (this
  machine cannot cross-compile any of the four targets; the stand-in exists so `build.sh`'s own real
  dirty-gate logic runs for real against a real git tree). Against that harness, the *unmodified*
  original `build-matrix.sh` fails at target 1 with the exact reported message; the fixed version
  completes all four targets, `sha256sum -c` verifies all four lines, and `git status --porcelain` is
  empty both during the run and after it. This exercises the ordering bug and its fix directly; it
  does not exercise real cross-compilation, real `ldd`/`readelf` output, or the real
  `aarch64-linux-musl-cross` download, none of which can run from this machine.

The same review's `SHOULD_FIX` findings are addressed alongside the four above: `scripts/install.sh`
now checks both `mv` calls it makes rather than reporting `installed:` and exiting 0 regardless of
whether either succeeded; the final install is staged under `$bin_dir` itself before the rename
rather than under `$work_dir` (commonly a different filesystem from the install prefix), so the
rename is a genuine same-filesystem atomic rename rather than one that degrades to copy-then-unlink
whenever `$TMPDIR` and `$bin_dir` differ; `scripts/install.sh` is now uploaded as a release asset (the
`gh release create` step lists it alongside the tarballs and `SHA256SUMS`), so the documented one-line
install command resolves instead of 404ing; the musl static-linkage check for the native
(`x86_64-unknown-linux-musl`) target now uses this repository's own, proven, wider pattern (`not a
dynamic executable\|statically linked`) instead of a narrower one that would reject a genuinely static
`static-pie` binary, and the foreign-architecture (`aarch64-unknown-linux-musl`) check now reads ELF
program headers directly (`readelf -lW` for a `PT_INTERP` entry) instead of running `ldd` against a
binary this runner cannot actually execute, which was untested by this repository before; the
`aarch64-linux-musl-cross` download is now checked against a `sha256` pinned by downloading the real,
current asset independently (twice, on two separate occasions) rather than trusted unverified, and the
checkout step in front of it sets `persist-credentials: false`, matching its sibling
`shell-selftests` job, since the credential a compromised tarball would otherwise run alongside is the
one this job uses to publish releases; and `NOTICE`, `LICENSE-APACHE`, and `LICENSE-MIT` are now
packaged into every tarball alongside `LICENSE` (verified against both `build-matrix.sh`'s own harness
run above and `release-selftest.sh`'s fixture tarball, listing all seven members, sorted, with the
expected modes).

**What this fix round could not verify, said plainly:** the `readelf -lW` foreign-architecture check
was not run against a real ELF binary anywhere (no `readelf` and no musl cross-toolchain are available
on this machine); the pinned `aarch64-linux-musl-cross.tgz` checksum was computed from a real download
but has never been exercised inside the actual `release-artifacts` CI job; and none of the four real
release-artifact builds, `verify-repro.sh` reaching a genuine green result, or the `gh release create`
step have run on Ubuntu. The `sh -n` and `bash -n` checks pass on all five scripts; no `shellcheck`
binary is available on this machine to run the acceptance criterion's `shellcheck` check at all, so
that specific check remains unrun here, not merely unreported.
