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
