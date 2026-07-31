# Supply chain: SBOM, signing, and provenance

This document is what we sign, what it proves, the exact commands to verify it, and what to do when
a check fails. Read alongside `docs/RELEASE.md` (the reproducible build the signatures rest on) and
`docs/THREAT-MODEL.md`'s "Installation and release artifacts" section (the threat model this whole
mechanism closes a gap in).

## 1. What we publish

Every release publishes, per tag:

- **Four tarballs**, one per shipped target (`x86_64`/`aarch64` times `gnu`/`musl`).
- **Four CycloneDX 1.6 SBOMs**, one per tarball, each describing exactly that artifact's resolved
  dependency closure for its own target and feature set.
- **One `SHA256SUMS`**, one line per tarball AND one line per SBOM (eight lines for a four-target
  release: `sha256sum *.tar.gz *.sbom.json`). Both `install.sh` and `verify.sh` select their own line
  by an exact, whitespace-delimited field match on the filename, never a substring search: a tarball's
  own filename is a byte-for-byte prefix of its SBOM's (`...tar.gz` of `...tar.gz.sbom.json`), and a
  substring match against this file would pick up both lines for a tarball whose SBOM was never
  downloaded.
- **Nine signatures**, one over each of the four tarballs, one over each of the four SBOMs, and one
  over `SHA256SUMS` itself, so a user who only wants to make one check has one to make. Each is a
  `<file>.bundle`: cosign's "new bundle format", a self-contained Sigstore bundle holding the
  signature, the short-lived Fulcio certificate, and an embedded Rekor inclusion proof together, so
  verification needs no live transparency-log search by artifact digest.
- **Four in-toto build provenance attestations**, one per tarball, as `<file>.intoto.bundle` (the
  identical bundle format, holding the DSSE-enveloped statement instead of a plain signature).

`scripts/install.sh`, `scripts/release/verify.sh`, and `scripts/release/sbom-licence-check.sh` are
themselves published release assets too (alongside the tarballs), so `verify.sh` can be downloaded and
run standalone, with no repository checkout, the same way `install.sh` already is. `deny.toml` and
`scripts/release/licence-exceptions.txt` are published release assets for the identical reason
(#788): `sbom-licence-check.sh`'s licence-subset check needs both, and a standalone `--sbom` run has no
repository checkout to find either one in otherwise. **None of these five files is signed or
checksummed**; they, and the licence check built from them, are transport trusted only -- see
`docs/THREAT-MODEL.md`'s "Installation and release artifacts" section for exactly what that does and
does not mean.

## 2. What a signature proves, and what it does not

A keyless `cosign` signature, verified with both `--certificate-identity-regexp` and
`--certificate-oidc-issuer` pinned, proves that a short-lived Fulcio certificate issued to this
project's own release workflow (`ci.yml`, running from a `v*` tag) signed these exact bytes, and that
the signature is recorded in a public transparency log a third party can independently audit. **It
does not, by itself, prove which commit, which build inputs, or which dependency graph produced the
artifact**, which is what the provenance attestation (section 4) is for, and it does not protect
against a compromise of the workflow itself while it is legitimately running, or a compromise of the
source before it was ever committed.

**A verification that omits either pin accepts a signature from anyone.** Dropping
`--certificate-identity-regexp` accepts a Fulcio certificate issued to any identity at all; dropping
`--certificate-oidc-issuer` accepts a certificate from any OIDC issuer Fulcio trusts, not only
GitHub's own. This is the single most common mistake with this tooling, which is why every command
below carries both, and why `scripts/release/supply-chain-selftest.sh` asserts it directly with a
negative test.

## 3. The exact verification commands

Download the artifact, its SBOM, `verify.sh`, `sbom-licence-check.sh`, and the two files the licence
check reads (`deny.toml`'s allowlist and its own exceptions list):

```sh
curl -fsSLO https://github.com/ELares/IronTraffic/releases/latest/download/irontraffic-<version>-<target>.tar.gz
curl -fsSLO https://github.com/ELares/IronTraffic/releases/latest/download/irontraffic-<version>-<target>.tar.gz.sbom.json
curl -fsSLO https://github.com/ELares/IronTraffic/releases/latest/download/verify.sh
curl -fsSLO https://github.com/ELares/IronTraffic/releases/latest/download/sbom-licence-check.sh
curl -fsSLO https://github.com/ELares/IronTraffic/releases/latest/download/deny.toml
curl -fsSLO https://github.com/ELares/IronTraffic/releases/latest/download/licence-exceptions.txt
```

The last two matter only for `--sbom`: `verify.sh --artifact` alone (no `--sbom`) never reads either
one. `sbom-licence-check.sh` looks for both beside itself first (this same flat directory, once they
are downloaded into it), the same way `verify.sh` looks for `sbom-licence-check.sh` beside itself.
**Both files are required together, not `deny.toml` alone**: if either one is missing, whether both are
absent or only `licence-exceptions.txt` is, the licence check reports itself SKIPPED, by name, rather
than failing (#788, widened by #791: a missing allowlist, or an incomplete one, says nothing about the
artifact and must never be reported as though it does). A run that DOES check the SBOM's licences
names both files' paths on its own `sbom licence: subset of the allowlist (...)` success line,
precisely so a shadowed or substituted copy of either file is never invisible in the one screen you
read.

Then verify (checksum, signature, and provenance; `--sbom` additionally checks the SBOM's own
signature and its licence set):

```sh
sh verify.sh --artifact irontraffic-<version>-<target>.tar.gz \
    --sbom irontraffic-<version>-<target>.tar.gz.sbom.json
```

Or, to reproduce exactly the checks `cosign` itself performs, without `verify.sh`:

```sh
cosign verify-blob \
    --bundle irontraffic-<version>-<target>.tar.gz.bundle \
    --new-bundle-format \
    --certificate-identity-regexp '^https://github\.com/ELares/IronTraffic/\.github/workflows/ci\.yml@refs/tags/v' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    irontraffic-<version>-<target>.tar.gz

cosign verify-blob-attestation \
    --bundle irontraffic-<version>-<target>.tar.gz.intoto.bundle \
    --new-bundle-format \
    --certificate-identity-regexp '^https://github\.com/ELares/IronTraffic/\.github/workflows/ci\.yml@refs/tags/v' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --type slsaprovenance \
    irontraffic-<version>-<target>.tar.gz
```

Verification is from a self-contained `.bundle` (signature, certificate, and an embedded Rekor
inclusion proof together), not a bare signature plus a live transparency-log search: that search-based
path was the first one this project shipped, and it failed against this project's own real signing
identity with a Rekor API error outside this project's control
(`proposedContent.proposedContent.verifiers in body is required`); the bundle format embeds the same
proof the search would otherwise look up over the network.

**`--sbom` is bound to the artifact, not merely checked on its own.** A signed SBOM proves this project
produced SOME SBOM; it does not, by itself, prove the SBOM describes the artifact being verified
alongside it. `verify.sh --sbom` therefore also compares the SBOM's own `irontraffic:target` property
against the target named in the artifact's filename, and its `irontraffic:cargo_lock_sha256` property
against `sha256(Cargo.lock)` as recorded in the artifact's own provenance attestation
(`cargoLockSha256`, section 4), the same digest `sbom.sh` and `attest.sh` each compute independently
from the one build. Either mismatch fails the check by name (`sbom binding: ...`), and this is what
invariant 8 asserts: without it, a signed SBOM from any target of any release verifies correctly beside
any tarball.

`scripts/install.sh` runs the first form (`verify.sh --strict`) automatically, on every install,
before anything is placed on `PATH`. The opt-out is explicit and prints a warning naming what is
skipped:

```sh
curl -fsSL https://github.com/ELares/IronTraffic/releases/latest/download/install.sh \
    | sh -s -- --no-verify-signature   # NOT RECOMMENDED
```

## 4. How to rebuild and compare

A signature proves this project produced the artifact from a stated commit; it does not prove that
commit produces the artifact. Reproducing the build is the complementary, stronger check, and is what
makes the whole chain checkable rather than merely asserted:

```sh
git checkout <commit printed by verify.sh as "source commit">
sh scripts/release/verify-repro.sh <target>
```

`verify-repro.sh` builds the named commit twice, at two different absolute paths, and asserts the two
binaries are byte-for-byte identical to each other; comparing the result against the digest
`verify.sh` reported closes the loop from "we said we built this" to "anyone can rebuild this and get
the same bytes."

## 5. What is in the SBOM that is not Rust

Every default-features SBOM describes a binary containing two vendored C libraries, both listed as
their own components (not merely as the Rust `*-sys` crate that wraps them, whose own crates.io
version is on an entirely independent numbering track from the C project it vendors):

- **aws-lc**, bundled via `aws-lc-sys` (or `aws-lc-fips-sys` for a `crypto-fips` build). Its version
  is read from the vendored source tree's own `AWSLC_VERSION_NUMBER_STRING`, not guessed from the
  wrapping crate's crates.io version.
- **zstd**, bundled via `zstd-sys`. `zstd-sys` itself encodes the vendored version as SemVer build
  metadata (`zstd-sys 2.0.16+zstd.1.5.7` vendors zstd `1.5.7`), which the SBOM generator reads
  directly.

A vulnerability scanner that only reads Rust crate names cannot match a CVE against either of these
by their real, upstream identity; this is why they are emitted as their own components rather than
left implicit in the Rust dependency list.

**As of this writing, `crates/irontraffic` (the release binary this SBOM describes) does not depend
on `crates/irontraffic-tls`, has no `tls` or `zstd` Cargo feature, and does not select a crypto
provider at all** (see `docs/RELEASE.md`'s "What this table does not yet say"). Neither vendored
library is therefore actually present in today's shipped SBOM; the mechanism above is real,
generic, and already exercised against a real dependency graph that has this exact shape today
(`crates/irontraffic-tls`'s own `crypto-aws-lc-rs` / `crypto-ring` features, used as the test fixture
in `scripts/release/supply-chain-selftest.sh`), and requires no change when a future issue wires TLS
into the release binary itself.

## 6. What to do if verification fails

| Failure | What it means | What to do |
| --- | --- | --- |
| Checksum mismatch | The download is corrupted, or the artifact was tampered with in transit | Re-download; if it recurs, do not run the binary |
| "certificate identity did not match" | Either the artifact was not produced by this project's release workflow, **or you omitted a pin** | Check your `cosign` command carries both `--certificate-identity-regexp` and `--certificate-oidc-issuer`; if it does and this still fails, treat the artifact as untrusted |
| Provenance subject digest mismatch | The attestation does not describe this exact file | Re-download both the artifact and its attestation together; do not mix files from different versions |
| A check was skipped and `verify.sh` exited nonzero | No network reached the transparency log, or a companion file (`.bundle`/`.intoto.bundle`) could not be found | This is the correct, safe default; re-run with network access, or pass `--allow-skipped` only if you understand what that check would have caught (see `docs/THREAT-MODEL.md`) |
| "sbom licence" is reported SKIPPED, reason "no deny.toml allowlist or licence-exceptions.txt found" | `sbom-licence-check.sh` could not find `deny.toml`, OR could not find `licence-exceptions.txt`, beside itself or at a repository root; **both are required together, `deny.toml` alone is not enough** (#788, widened by #791) | Not tampering, and not a licence violation either: fetch `deny.toml` and `licence-exceptions.txt` per section 3 and re-run, or pass `--allow-skipped` if you accept not making this one check |
| "sbom licence" is reported SKIPPED, reason "SBOM declares zero components" | `deny.toml` and `licence-exceptions.txt` were both found, but the SBOM itself lists no components at all, so there is nothing to check its licences against (#791) | Confirm by hand that this artifact genuinely has zero dependencies; if it does not, treat the SBOM as corrupted or mismatched and re-download it |
| SBOM licence check names a component | A dependency's declared licence, or a compound expression's disjunct, is not on the `deny.toml` allowlist, and `deny.toml` AND `licence-exceptions.txt` were both found and applied to reach this comparison (named on the `applied:` line in the output above this failure; #791 closed the half-installed guard that could previously accuse a component with an incomplete allowlist) | This should not happen in a published release; report it |
| `install.sh` refuses | Any of the above, or verification was simply unavailable | Investigate before passing `--no-verify-signature`; that flag is a deliberate downgrade, not a workaround |

## 7. Our licence allowlist

The same allowlist `cargo deny check` gates the build with, read from `deny.toml`'s `[licenses]
allow` list directly by `scripts/release/sbom-licence-check.sh` (not a copy of it, so the two cannot
silently drift apart): MIT, Apache-2.0, `Apache-2.0 WITH LLVM-exception`, BSD-2-Clause, BSD-3-Clause,
ISC, Zlib, Unicode-3.0, CC0-1.0, MIT-0. Both `deny.toml` (repository root) and
`scripts/release/licence-exceptions.txt` are published release assets (#788), landing at
`deny.toml` and `licence-exceptions.txt` respectively, so a standalone `verify.sh --sbom` run (section
3) can fetch the same allowlist a checkout already has beside it.

Every component's licence set (and every disjunct of a compound SPDX expression, such as
`MIT OR Apache-2.0` or the legacy `MIT/Apache-2.0` spelling some crates still use) must be a subset of
that list. This is deliberately stricter than `cargo deny`'s own SPDX-aware evaluation, which accepts
a compound expression as soon as any one disjunct is allowed: a component whose licence choice is
legitimately looser gets a written, committed entry in `scripts/release/licence-exceptions.txt`
(`<purl>` and a reason of at least 20 characters) rather than passing silently. As of this writing that
file has three entries, all found by running the real SBOM generator against this workspace's own
current dependency closure: `aho-corasick` and `memchr` (`Unlicense OR MIT`, where the `MIT` disjunct
alone satisfies the allowlist) and `ryu` (`Apache-2.0 OR BSL-1.0`, where the `Apache-2.0` disjunct
alone satisfies it).

## Why CycloneDX, not SPDX

The Rust tooling for CycloneDX consumes `cargo metadata` directly and emits component identifiers as
`pkg:cargo/<name>@<version>` purls, which is what a downstream vulnerability scanner matches on; that
is the whole reason, stated as a preference rather than a judgement that SPDX is wrong. An SPDX
document is addable later if a consumer asks for one, from the same dependency graph this generator
already computes; it is not a redesign.

## Why "reachable from a signed tag" does not mean a GPG-signed git tag

`scripts/release/verify.sh --strict` requires that the build's own recorded ref (from the provenance,
already fetched and already cryptographically verified as part of the signature check) matches
`refs/tags/v*`, rather than walking local git history for a GPG- or gitsign-signed tag object. Two
reasons, both load-bearing: `scripts/install.sh` always passes `--strict`, and the documented
`curl | sh` install has no local git checkout at all to walk; and this project does not GPG- or
gitsign-sign its git tag objects today (only the *artifacts* are signed, keylessly, by cosign). The
certificate identity pin in section 2 already cryptographically proves the build ran from a `v*` tag
ref via Fulcio and a public transparency log, which is independently stronger evidence than a local,
unauthenticated `git tag --contains` walk would have been; `--strict`'s ref check restates that same,
already-verified fact rather than adding a new trust mechanism this project has not built.
