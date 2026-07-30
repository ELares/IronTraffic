# Changelog

All notable changes to IronTraffic are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository foundation: Cargo workspace, pinned toolchain, and the merge gate.
- The invariant lints and their self-test, the PR scope check, and the dependency policy.
- Governance: architecture, covenants, threat model, non-goals, and the implementer handbook.
- OCSP stapling: request building, strict response validation over attacker-controlled bytes, a
  sans-IO staple updater with exponential backoff and jitter, an SSRF gate on the responder URL
  (`OcspConfig`), and a fail-closed refusal to install, replace, or set as default a must-staple
  certificate with no OCSP staple attached.
