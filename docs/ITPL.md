# ITPL: the IronTraffic Policy Language

ITPL is a CEL-syntax-compatible, statically typed, total expression language
that compiles to flat bytecode at config-admission time. It is layer 1 of the
four-layer extension surface.

ITPL has no loops, no recursion, no user-defined functions and no
comprehensions. Every expression terminates in `O(e)` where `e` is its bytecode
length, by construction. That is the reason to build a language instead of
embedding a Turing-complete one: a policy that can loop is a policy that can hang
a worker. Measured on the reference host, the `cel` crate evaluating
`path.startsWith("/v1/") && method == "GET"` costs 227.5 ns with a reused
`Context` and 1,492.5 ns building a fresh `Context` per request. A proxy must
build a fresh context per request, so 1.5 microseconds is the real number. A
slot-indexed evaluator over the same predicate measured 10.8 ns.

## Grammar

```ebnf
expr        = ternary ;
ternary     = or [ "?" expr ":" expr ] ;
or          = and { "||" and } ;
and         = rel { "&&" rel } ;
rel         = unary [ relop unary ] ;
relop       = "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" ;
unary       = { "!" } postfix ;
postfix     = primary { field | index | call } ;
field       = "." IDENT ;
index       = "[" expr "]" ;
call        = "." IDENT "(" [ expr { "," expr } ] ")" ;
primary     = IDENT | INT | STRING | "true" | "false" | "null" | "(" expr ")" | list ;
list        = "[" [ expr { "," expr } ] "]" ;

IDENT       = ( ALPHA | "_" ) { ALPHA | DIGIT | "_" } ;
INT         = [ "-" ] DIGIT { DIGIT } ;
STRING      = '"' { CHAR | ESCAPE } '"' | "'" { CHAR | ESCAPE } "'" ;
ESCAPE      = "\\" ( "n" | "r" | "t" | "\\" | '"' | "'" | "0"
                   | "x" HEX HEX | "u" HEX HEX HEX HEX ) ;
```

Precedence, loosest to tightest: ternary, `||`, `&&`, relational, unary `!`,
postfix. `&&` and `||` are left associative and short circuit. The ternary is
right associative.

## Closed method set

The only method names a `call` may use are:

- `startsWith("/v1/")` - true when the receiver string begins with the argument.
- `endsWith(".json")` - true when the receiver string ends with the argument.
- `contains("admin")` - true when the receiver string contains the argument.
- `matches("^v[0-9]+")` - true when the receiver matches the regular expression.
- `equalsIgnoreCase("GET")` - case-insensitive equality.
- `startsWithIgnoreCase("/api")` - case-insensitive prefix check.
- `size()` - number of elements in a list or bytes in a string.

## Attributes

ITPL's attribute schema is closed: an expression may only read one of the 25 scalar
attributes or index into one of the 3 maps below. There is no "get property by
arbitrary path" surface. Reading `response.status` in a phase before the response
exists, or reading an attribute that is not in this table at all, is a config error at
admission, never a runtime `null`.

### Scalar attributes

| path | type | available from |
| --- | --- | --- |
| `request.method` | string | `request_headers` |
| `request.path` | string | `request_headers` |
| `request.query` | string | `request_headers` |
| `request.scheme` | string | `request_headers` |
| `request.authority` | string | `request_headers` |
| `request.host` | string | `request_headers` |
| `request.port` | int | `request_headers` |
| `request.protocol` | string | `stream_start` |
| `request.size` | int | `request_headers` |
| `request.id` | string | `request_headers` |
| `request.header_count` | int | `request_headers` |
| `connection.remote_addr` | string | `stream_start` |
| `connection.remote_port` | int | `stream_start` |
| `connection.local_addr` | string | `stream_start` |
| `connection.tls` | bool | `stream_start` |
| `connection.sni` | string | `stream_start` |
| `connection.alpn` | string | `stream_start` |
| `connection.mtls_verified` | bool | `stream_start` |
| `connection.listener` | int | `stream_start` |
| `route.id` | int | `route_selected` |
| `route.cluster` | int | `route_selected` |
| `response.status` | int | `response_headers` |
| `response.size` | int | `response_headers` |
| `stream.id` | int | `stream_start` |
| `stream.duration_ms` | int | `log` |

`connection.sni` is available in every phase, but a plaintext connection has no SNI:
it reads as the empty string, not `null`, because the connection itself exists even
when there was no TLS handshake to name a server.

**`connection.remote_addr` is the peer, not the client.** Behind a load balancer, a
CDN, or any other proxy it names that intermediary's address, and a policy that
allow-lists an address range using it is allow-listing the intermediary, not whoever
originated the request. The originating client address depends on forwarded-header
handling and a trusted-hop configuration that lives in the HTTP layer, not in ITPL, so
there is deliberately no `request.client_ip` attribute in v1: ITPL cannot know what a
deployment trusts, and an attribute that silently trusted the first
`request.headers["x-forwarded-for"]` entry would be a spoofing bug in a convenient
package. Reading `request.headers["x-forwarded-for"]` directly is permitted; believing
it without a trusted-hop configuration is the bug, and that responsibility stays with
whoever writes the policy.

### Indexable maps

Each of these requires a string-literal key; a computed key
(`request.headers[request.method]`) is rejected at admission (`DynamicIndex`), because
a header name computed per request would defeat interning and would create a way to
probe for header presence with a computed name.

| path | element type | available from | key casing |
| --- | --- | --- | --- |
| `request.headers` | string or null | `request_headers` | lowercased |
| `request.query_params` | string or null | `request_headers` | case sensitive |
| `response.headers` | string or null | `response_headers` | lowercased |

`request.headers` and `response.headers` go through `FieldSection::get_unique`, which
returns an error when a header name appears more than once; ITPL maps that to `null`.
It never joins repeated values with commas: that is Envoy CVE-2026-26308, where the
RBAC filter concatenated repeated headers before matching and a request carrying the
same header twice bypassed policy.

**Absent means `null`, and `null` compares equal to nothing except `null`.** A missing
header is `null`, so `request.headers["x-a"] == "b"` is false and
`request.headers["x-a"] == null` is the absence test. `request.headers["x-a"] == ""`
is also false for a request that never sent the header: reading absence as empty
string would make that comparison true and would be a policy bypass waiting to
happen.

**`null` is the safe answer in one direction only.** An allow-list predicate
(`request.headers["x-key"] == "secret"`) becomes `false` under a duplicated header,
which denies, and is safe. A deny-list predicate (`request.headers["x-blocked"] !=
"yes"`) becomes `true` under the same duplication, which admits, so a peer bypasses it
by sending the header twice. `null` alone does not close this: the evaluator also
records that a duplicate was observed, and the policy filter treats a
duplicate-influenced result as a filter failure for the fail-closed kinds. The unsafe
spelling to avoid is writing `request.headers["x-debug"] == null ||
request.headers["x-debug"] != "1"` and believing that closes the gap; it does not, the
duplicate-influenced failure rule does.

Query parameter names are case sensitive and are never lowercased; header names are
always lowercased, for both of the header maps, because `FieldSection` stores them
canonical and field names are themselves case insensitive at the HTTP layer.

### Availability matrix

An attribute or map is available from the phase named above through `log` inclusive.
The full matrix, one row per attribute:

| attribute | stream_start | request_headers | request_body | request_trailers | route_selected | upstream_request_headers | response_headers | response_body | response_trailers | log |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `request.method` |  | x | x | x | x | x | x | x | x | x |
| `request.path` |  | x | x | x | x | x | x | x | x | x |
| `request.query` |  | x | x | x | x | x | x | x | x | x |
| `request.scheme` |  | x | x | x | x | x | x | x | x | x |
| `request.authority` |  | x | x | x | x | x | x | x | x | x |
| `request.host` |  | x | x | x | x | x | x | x | x | x |
| `request.port` |  | x | x | x | x | x | x | x | x | x |
| `request.protocol` | x | x | x | x | x | x | x | x | x | x |
| `request.size` |  | x | x | x | x | x | x | x | x | x |
| `request.id` |  | x | x | x | x | x | x | x | x | x |
| `request.header_count` |  | x | x | x | x | x | x | x | x | x |
| `request.headers` |  | x | x | x | x | x | x | x | x | x |
| `request.query_params` |  | x | x | x | x | x | x | x | x | x |
| `connection.remote_addr` | x | x | x | x | x | x | x | x | x | x |
| `connection.remote_port` | x | x | x | x | x | x | x | x | x | x |
| `connection.local_addr` | x | x | x | x | x | x | x | x | x | x |
| `connection.tls` | x | x | x | x | x | x | x | x | x | x |
| `connection.sni` | x | x | x | x | x | x | x | x | x | x |
| `connection.alpn` | x | x | x | x | x | x | x | x | x | x |
| `connection.mtls_verified` | x | x | x | x | x | x | x | x | x | x |
| `connection.listener` | x | x | x | x | x | x | x | x | x | x |
| `stream.id` | x | x | x | x | x | x | x | x | x | x |
| `route.id` |  |  |  |  | x | x | x | x | x | x |
| `route.cluster` |  |  |  |  | x | x | x | x | x | x |
| `response.status` |  |  |  |  |  |  | x | x | x | x |
| `response.size` |  |  |  |  |  |  | x | x | x | x |
| `response.headers` |  |  |  |  |  |  | x | x | x | x |
| `stream.duration_ms` |  |  |  |  |  |  |  |  |  | x |

A policy attached to `on_request_headers` cannot read the response status; a policy
attached to `on_log` can read everything. Reading an attribute before its phase is a
config error naming the attribute and the phase, not a runtime `null`: Envoy's CEL
activation has no equivalent check, and an attribute that is not populated there
yields an error value that most expressions silently absorb.

## Equality and ordering

`==` and `!=` require both sides to have the same type, except that the `null`
literal unifies with a `string`, `int` or `bool` operand for equality only; comparing
two `map`s or a `list` against anything, including another `list`, is a type error.
Relational operators (`<`, `<=`, `>`, `>=`) require both sides to be `int`; there is no
ordering for strings in v1, because byte order is rarely what an operator means and
locale order is not something a proxy should imply.

**String equality in ITPL is not constant time.** `==` on a string is a length compare
and a byte compare that stops at the first difference, so the time it takes leaks how
long a shared prefix is. That is fine for a path or a method and it is a credential
oracle for `request.headers["x-api-key"] == "s3cret"`, which is a policy an operator
will write. ITPL is a routing and policy language, not a credential verifier, and the
language cannot detect that intent; verifying a presented key in constant time is
`api-key-mint-and-constant-time-verify` (#351).

## Rejected CEL constructs

The following CEL constructs are not implemented and produce a `NotImplemented`
error naming the construct:

- `has`, `all`, `exists`, `exists_one`, `map`, `filter`
- `type`, `dyn`, `int`, `uint`, `double`, `bytes`, `string`, `duration`, `timestamp`
- any `.` call whose name is not in the closed method set above

Use the appropriate method from the closed set instead of string functions.
There is no `lower()` or `upper()`; `equalsIgnoreCase` and
`startsWithIgnoreCase` exist so evaluation does not allocate new strings.

## Limits

| field | default | hard cap |
| --- | --- | --- |
| `max_source_bytes` | 8,192 | 65,536 |
| `max_tokens` | 1,024 | 8,192 |
| `max_string_bytes` | 1,024 | 8,192 |
| `max_depth` | 16 | 16 |
| `max_ops` | 256 | 4,096 |
| `max_consts` | 128 | 1,024 |
| `max_attr_slots` | 16 | 16 |
| `max_regex` | 8 | 64 |
| `max_regex_size` | 65,536 | 1,048,576 |
| `max_list_elems` | 64 | 1,024 |

## When not to use ITPL

From the science document: the four-layer rule. Layer 1, ITPL, is for predicates
and projections that fit in a single expression against already-parsed request
state. Layer 2 is for simple mutation, header rewriting and local routing under
a scratch cap. Layer 3 is for stateful per-request logic that needs a real
runtime. Layer 4 is for external callouts. If a policy needs to call a network
service, maintain mutable state across requests, or run unbounded computation,
it belongs in a higher layer, not in ITPL.

## Notes

- Identifiers are case sensitive everywhere.
- `in` is a keyword and cannot be used as a field name.
- Comments are not part of v1; `#` and `//` are unexpected bytes.
- String literals may span lines.
- String values are byte strings; `\xHH` may produce any byte value.
- There is no arithmetic in v1.
