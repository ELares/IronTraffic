# contract/openapi.v1.json

This file is the source of truth for the v1 admin API. It is hand maintained,
not generated, and the admin API implementation is gated against it rather
than the other way around: the crate that serves this API generates its own
document (`schema/openapi.json`) from its handlers, and a route census asserts
that every operation the router actually serves appears in this file with the
same method, path and `operationId`. When the two disagree, the disagreement
is a bug in one of them, and it is resolved here, not papered over in the
console or the CLI.

## What is frozen

The set of operations, their paths, their methods, their `operationId` values
and their required permissions are frozen. Changing any of them is a
deliberate, reviewable edit to this file: open a pull request against it like
any other change, and update `x-it-operation-count` in the same commit so an
accidental deletion is loud rather than silent.

The response schemas are not frozen in the same sense. Every operation ships
with `Envelope` and an unconstrained `data` member from day one, and a later
screen issue narrows that member to a named schema as it renders the
operation's data. That is deliberate: the shape of the data a screen displays
is decided by the issue that displays it.

## What validates it

`scripts/api-contract-check.sh` is the mechanical half of "frozen". It parses
this file and asserts its internal consistency and its house rules: every
operation carries a permission from the closed vocabulary in
`x-it-permissions`, every mutating operation carries the headers this project
requires, every path parameter is bounded, every `$ref` resolves, and every
component is used by something. Run it with no arguments to check the
committed document, or with `--selftest` to run its own fixtures.

`x-it-cli` is not decoration. It is what the parity gate in the dashboard CI
gates issue, and the command table in the `irtctl` crate, are derived from:
both read this field rather than maintaining their own copy of the command
list, so neither can drift from what this document says the command is.
`scripts/api-contract-check.sh` also rejects any `x-it-cli` value containing
a shell metacharacter, because the parity gate executes these values against
a fixture server.

## Routing rules a checker cannot see

A literal path segment outranks a template segment at the same position. The
paths `/config/freeze` and `/config/versions` are two segment literals that
also match the template `/config/{kind}`, and the router must resolve the
literal first. For that reason `freeze` and `versions` are reserved: neither
may ever be used as a configuration resource kind, and this document never
declares a `kind` value of either.

Every configuration resource is addressed with a namespace segment, always.
The path template is `/config/{kind}/{ns}/{name}`; the two segment form
`/config/{kind}/{name}` does not appear in this document and must not be
added, because two path templates for one resource means two client code
paths, two cache keys, and two places a permission check can be forgotten. A
cluster scoped resource, which has no namespace of its own, uses the reserved
namespace literal `default`.

Neither of these two rules can be checked mechanically from this document
alone, because the two segment form is simply absent rather than present and
wrong. They are enforced by review: a pull request that reintroduces the two
segment form, or that uses `freeze` or `versions` as a resource kind, is
rejected on sight.

## Authentication and authorization

`"none"` is a permission check sentinel. It means "any authenticated
principal", and it never means "unauthenticated". Exactly three operations
carry it: `getWhoami`, because a caller must be able to discover that it has
no permissions, and `getSchema` and `getOpenapi`, because the two
specification documents contain no operator data. There is no configuration
of IronTraffic in which any operation in this document is reachable over a
network socket without authentication, and an unauthenticated request to any
of those three is `401`, exactly like an unauthenticated request to
`deleteConfigResource`.

Authorization is decided before existence. For every operation, the server
checks authentication, then authorization, then whether the addressed
resource exists. A caller lacking the operation's permission receives `403`
with `missing_permission` whether or not the resource exists, and never
`404`. A caller who holds the permission receives `404` for a resource that
is genuinely absent. Without this ordering an under privileged principal
enumerates namespaces, route names, consumer identifiers and certificate
identifiers by watching `403` turn into `404`, which is a disclosure that no
amount of filtering on the response body prevents. The `Idempotency-Key` and
`If-Match` checks follow the same ordering: both happen after authorization,
so neither can be used to probe for a resource.

`GET /ui/{*path}` and `GET /metrics` require authentication like every
operation in this document. `/metrics` in particular exposes route names,
upstream names, certificate subjects and traffic volumes, and is a gift to
anyone who can read it without holding a session. Only `GET /healthz` and
`GET /readyz` may answer without authentication, and they return a fixed body
that names no resource and no version.

A principal may always revoke its own session. `revokeSession` requires
`sessions:manage` to revoke another principal's session, but revoking the
session the request itself is authenticated with succeeds for any
authenticated caller, because that is the log out path and a console that
cannot log out has only the idle timeout to end a session. This is recorded
on the operation's `description` as well as here. It is the only place in
this document where the effective permission depends on the object being
acted on, and it is safe in the one direction that matters: it can only ever
destroy the caller's own authority, never another principal's.

## Cursors are not server state

A `cursor` is attacker controlled input, not a serialized offset the caller
can be trusted to hand back unchanged. It carries a bounded length and a
closed character class so a malformed one is rejected before any decoding
happens, and it is re-authorized on every use against the caller's
permissions at that moment. A cursor must never be a plain serialized
namespace, key or offset that a caller can edit to page past an
authorization boundary; whatever it encodes is checked again, every time, not
trusted because it was returned by the server on a previous page.
