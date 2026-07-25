<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
## Summary

Closes #

<!-- What this PR does, in two or three sentences. -->

## Checklist

- [ ] `scripts/gate.sh` is green locally.
- [ ] The diff touches ONLY the files the issue's `## Files` table declares. (CI enforces this. If
      the scope genuinely had to grow, I edited the issue and explained why below.)
- [ ] Every acceptance criterion on the issue is met, and I checked them off on the issue.
- [ ] Every test the issue names exists and asserts what the issue says it asserts.
- [ ] No `todo!()`, `unimplemented!()`, stubbed return, `#[ignore]`, or assertion-free test.
- [ ] No new dependency, or the issue authorized it and `Cargo.toml` carries the justifying comment.
- [ ] **Threat model rule**: this PR ships no new surface, OR `docs/THREAT-MODEL.md` gains that
      surface's section in this PR. See CONTRIBUTING.md.
- [ ] `CHANGELOG.md` (Unreleased) updated for user-visible changes.
- [ ] No em dashes or en dashes anywhere in the diff.

## Notes for the reviewer

<!-- Anything surprising. If you used an `it-allow:` escape, justify it here too. -->
