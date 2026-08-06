# The desync differential harness

This document specifies the contract for the live, homegrown request-smuggling differential
harness the dataplane milestone builds. Nothing here is implemented yet: milestone 2 (this
repository's HTTP parse boundary) has no forwarding loop and no live IronTraffic process to place
in front of anything, so the harness itself is out of scope for it. What milestone 2 delivers is
the corpus this harness replays (`corpus/h1-heads.txt`, `corpus/paths.txt`, `corpus/chunked.txt`,
`corpus/mplex.txt`, `corpus/forwarded.txt`) and this specification, so the dataplane milestone can
build the harness from this document and the corpus alone, without re-deriving either.

## Why a differential harness, and why it cannot be a unit test

Smuggling is a two-parser property. Every unit test in this milestone's issues proves what
IronTraffic itself decides about one message; none of them can prove that IronTraffic's decision
agrees with a REAL origin's decision about the SAME bytes. A front end and a back end that each
individually behave "correctly" by their own parser's rules can still disagree about where one
request ends and the next begins, and that disagreement is exactly what smuggling exploits. The
only test that actually demonstrates the defence is one that puts a real front end in front of a
real back end and counts requests on the wire between them.

## The five origin servers

The harness runs IronTraffic in front of each of these five, one at a time, unmodified and at
their own default HTTP/1.1 parsing settings (no origin-side hardening flags): NGINX, Apache httpd,
Node.js (`http` module), Go `net/http`, and Gunicorn. These five were chosen because each has a
documented history of disagreeing with at least one other popular HTTP/1.1 implementation on some
corner of request-line, field-line, or chunked-body framing, which is exactly the disagreement
surface a front end must close rather than merely narrow.

## The replay procedure

For every corpus entry, in every one of the five corpus files:

1. Decode the entry's byte field with the same escape rules `corpus/*.txt`'s own header comments
   document (`\r`, `\n`, `\t`, `\0`, `\\`, `\xHH`), plus, for `corpus/forwarded.txt`, the `f:`,
   `x:` and `p:` marker convention those files use to select which consumer an entry drives.
2. Start a fresh backend instance of the origin under test and a fresh IronTraffic process
   configured to forward to it, with counting middleware or an access log the harness can use to
   count requests the backend actually received on its own listening socket.
3. Open one connection to IronTraffic and write the decoded bytes to it, exactly as recorded,
   with no reframing, and with connection reuse where the entry's own outcome expects the
   connection to stay open (an `ok` head-corpus entry with a pipelined second request; an `ok`
   chunked-corpus entry followed by more input on the same connection).
4. Record, for that one entry, the exact number of requests the backend's own counting layer
   observed.
5. Tear down both processes (a fresh backend and a fresh IronTraffic per entry keeps one entry's
   connection state from leaking into the next entry's count) and repeat for the next entry.

Every corpus entry is replayed against every one of the five origins independently: an entry that
IronTraffic refuses must produce ZERO backend requests on every origin, and an entry IronTraffic
forwards must produce a backend request count the harness can reconcile against what the corpus
entry's own decoded bytes actually contain (one request for a single well-formed message, two for
the pipelined `ok` entry in `corpus/h1-heads.txt`, and so on).

## The one assertion

For every corpus entry, on every one of the five origins:

> **The backend never sees more requests than IronTraffic forwarded.**

That is the entire assertion, stated once because it is the only one that actually proves the
smuggling defence: everything else (an exact reject reason, an exact normalized path, an exact
`consumed` value) is already pinned by the unit corpus this document's sibling files drive
(`crates/irontraffic-http/tests/corpus.rs`, `crates/irontraffic-conn/tests/corpus_proxy.rs`), and
re-asserting it here would test IronTraffic against itself rather than against a real second
parser. A violation of this one assertion, on any entry against any origin, is a live smuggling
primitive: the backend parsed the bytes IronTraffic forwarded as MORE requests than IronTraffic
itself believed it was sending, which is exactly the "front end and back end disagree about
framing" condition this whole milestone exists to make unrepresentable.

## What this document deliberately does not specify

The wire format of the counting middleware or access-log convention each of the five origins
uses, the process-supervision mechanism that starts and tears down a fresh backend and a fresh
IronTraffic per entry, and the container or CI-lane plumbing that hosts all of it are all
implementation choices for whichever issue in the dataplane milestone builds this harness. This
document fixes only the five origins, the replay procedure, and the one assertion, because those
three are the parts a later implementer cannot recover from the corpus alone.
