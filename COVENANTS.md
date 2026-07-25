# The IronTraffic covenants

These commitments are made once, publicly, at the start of the project, and they do not move. Every
one of them exists because it is the documented behavior of a named competitor in this category. If
a future version of IronTraffic violates any covenant on this page, treat that as a breaking change
of the project itself, and say so publicly.

Each covenant is written to be **falsifiable**. A promise you cannot check is marketing.

## The four inviolable lines

1. **No paywalled security or correctness.** Authentication, authorization, rate limiting, mutual
   TLS, audit logging, request validation, WAF integration, multi-tenancy, and every fix for a
   security defect ship to everyone, in the open source project, including when self-hosted.
   This exists because the pattern in this category is to sell exactly these: OIDC, sliding-window
   rate limiting, admin RBAC, and request validation are all behind an enterprise line at one or
   more major competitors today, and at least one shipped a request-smuggling fix only to its paid
   editions.

2. **No capability is deleted from the open source project and sold back.** A working open source
   feature is never removed and re-offered as a commercial add-on. This exists because clustered
   certificate management was present in one competitor's 1.x, removed in 2.0, and is now sold as
   part of its commercial tier, with the vendor's own documentation directing multi-replica users to
   buy it.

3. **No mandatory first-party infrastructure.** IronTraffic runs complete standalone with no
   database, no key-value store, no external cache, and no service registry. IronCache and IronBus
   are strictly optional accelerators behind documented interfaces with safe defaults; they are
   never prerequisites, and CI verifies the no-dependency path on every pull request.

4. **No unexportable configuration or state.** Every piece of configuration, every certificate, and
   every piece of operator-visible state is exportable through documented, self-serve interfaces.
   Leaving IronTraffic must never require a support ticket, and the export format is the same one
   the product ingests.

## Supporting commitments

- **No two-tier security patching.** Security fixes ship to everyone simultaneously. There is no
  tier that receives interim patches while others wait.

- **No per-unit pricing traps.** No metering of requests, routes, certificates, dashboard seats,
  environments, or nodes, and no retroactive monetization of previously free capabilities.

- **No telemetry.** IronTraffic does not phone home. It collects no usage analytics, sends no
  installation beacon, and has no opt-out to configure because there is nothing to opt out of.

- **No mid-flight relicensing.** The license is OSI-approved (MIT or Apache-2.0, at your option) and
  stays that way. The commercial line below is stated now precisely so a future relicensing cannot
  be justified as clarifying it. Two major infrastructure projects adjacent to this category moved
  to non-open licenses after building their communities; this sentence exists so that our doing the
  same would be unambiguously a broken promise rather than a reinterpretation.

- **No dishonest numbers.** Every performance figure IronTraffic publishes carries the hardware, the
  version, the date, and the methodology, and is reproducible by a script committed to this
  repository. We do not publish a number we cannot reproduce, and we do not benchmark with the
  safety features turned off.

## The commercial line, stated up front

If a commercial offering ever exists, it may charge for: managed hosting, operating the platform at
scale on your behalf, support contracts and service level agreements, and compliance evidence packs.
It may not charge for anything the four inviolable lines or the supporting commitments cover.

This paragraph is here so the covenant is falsifiable: if a paid feature ever appears that is not on
that list, the covenant is broken, and the community should say so.
