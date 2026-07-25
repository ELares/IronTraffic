# Security policy

IronTraffic is pre-1.0 and under active foundational development. No production deployment should
exist yet. Until a stable 1.0, the latest release is the only supported version.

IronTraffic terminates hostile traffic by design, so its security posture is the product. The
per-surface threat model lives in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and is extended in
the same pull request that ships any new surface.

## Reporting a vulnerability

Report suspected security issues privately. Do not open a public issue for a vulnerability.

- Preferred: GitHub private vulnerability reporting on this repository, the "Report a vulnerability"
  button under the Security tab.
- A dedicated security inbox will be published here once project infrastructure exists; until then
  the GitHub channel is authoritative.

## What to expect

- Acknowledgement within 3 business days.
- Initial assessment (accepted, declined, or needs more information) within 7 business days.
- Coordinated disclosure: we ask for up to 90 days to ship a fix, we will agree a timeline with you,
  and we credit you in the advisory if you wish. If a fix ships sooner, disclosure moves up
  accordingly, never later without your agreement.

## Safe harbor

We will not pursue or support legal action against good-faith security research on IronTraffic. Good
faith means testing against your own deployment, no degradation of infrastructure you do not own, no
exfiltration beyond the minimum proof needed, and private reporting per this policy.

Per [COVENANTS.md](COVENANTS.md), there is no two-tier security patching: fixes ship to everyone at
the same time, and no security capability is ever behind a commercial edition.
