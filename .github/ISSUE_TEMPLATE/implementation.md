---
name: Implementation issue
about: A complete implementation contract. Every section is required.
title: ''
labels: ''
assignees: ''
---

<!--
This template is the rubric. An issue that does not fill in every section is not
ready to be worked on. The reasoning happens HERE, once, so the implementer can
execute without having to infer intent. See AGENTS.md for the standing rules.
-->

## Summary

<!-- Two to four sentences: the deliverable, and the one-sentence reason it exists. -->

## Context

<!-- Everything the implementer needs that is not yet in the code, INLINED. May reference other
issues, but must be independently sufficient. Never write "see the design doc for the algorithm"
without reproducing the algorithm here. -->

## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/.../src/....rs` | create | |

<!-- Files not in this table MUST NOT be touched. CI enforces it. -->

## Design

<!-- The data structures written out as Rust. The algorithm as numbered steps, not a description of
an algorithm. The complexity as a table with variables defined, average AND worst case. The
invariants as assertions. Two sentences on why this design and not the obvious alternative, so the
implementer does not "improve" it into the alternative. -->

## Public API

```rust
// Every public item this issue adds or changes, as compiling Rust:
// full signatures, bounds, error types, and doc comments.
```

## Edge cases

<!-- Numbered, each with its required behavior. Empty input, single element, maximum size, duplicates,
boundaries (0, 1, max, max+1), malformed and non-UTF-8 input, percent-encoded and unicode forms,
concurrent access, dependency unavailable, retry after partial failure. -->

## Acceptance criteria

- [ ] <!-- Externally verifiable. "Works correctly" is not a criterion. -->

## Tests

<!-- Every required test by name, with its exact assertion and location. Unit, property (state the
property and the generator), and fuzz (state the target and the must-not-panic contract). -->

## Benchmarks

<!-- For anything on the request path: the criterion benchmark name, what it measures, the budget it
must meet. Otherwise: "not on the request path" and why. -->

## Do NOT

<!-- Issue-specific prohibitions. Never empty. Standing rules live in AGENTS.md. -->

## Dependencies

**Blocked by:** <!-- issue numbers, with one line each on what they provide, or "None." -->
**Blocks:** <!-- issue numbers -->

## References

<!-- Exact locators: RFC number AND section, paper title AND the result used, competitor source file
AND function, CVE id. Never a bare homepage link. -->
