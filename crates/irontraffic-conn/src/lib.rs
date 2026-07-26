// SPDX-License-Identifier: MIT OR Apache-2.0

//! Listener binding and connection lifecycle.
//!
//! # The reuseport skew story, stated rather than hidden
//!
//! The kernel selects the receiving socket by hashing the connection 4-tuple. If all
//! traffic arrives from one source IP with few source ports (a single NAT, a single
//! sidecar, a CDN-to-origin link, or an attacker), the hash concentrates and one shard
//! can receive O(c) of c connections. In `balanced` mode this is absorbed at no extra
//! cost, because a connection task can be stolen by any worker after accept, so kernel
//! skew becomes task skew and the work-stealing scheduler resolves it. It would be a
//! genuine denial-of-service vector in a shared-nothing mode, which is one reason
//! `balanced` is the default.
//!
//! Sharding is still the right default: with a single shared socket, epoll wakeups are
//! last-in-first-out, so the busiest worker gets most of the load, measured by
//! Cloudflare as one worker at 30% CPU with the others idle.
//!
//! # Who else can be in the reuseport group
//!
//! `SO_REUSEPORT` means another local process can bind the same address and receive a
//! share of our connections. On Linux the kernel requires every socket in the group to
//! have the same effective UID as the one that created it, so the precondition is a
//! process running as the same user; that check is a Linux behaviour and is not
//! guaranteed elsewhere. Run the proxy as a dedicated user account. This is the same
//! mechanism a future binary upgrade relies on deliberately, which is why it is
//! documented rather than blocked.
//!
//! # Descriptor budget
//!
//! `L x W` listening descriptors, at most 64 x 1024 = 65,536 given the validator's
//! listener cap and the runtime's worker cap, plus two descriptors per live connection.
//! The startup path checks that total against `RLIMIT_NOFILE` before binding.
//!
//! # How connections spread across shards
//!
//! The skew story above is only half the argument without the numbers behind it. These
//! are the three rows of the crate's complexity budget that describe how load actually
//! lands on a shard, carried here rather than left only in the design document.
//!
//! | Operation | Average | Worst case | Space |
//! | --- | --- | --- | --- |
//! | Kernel socket selection per connection | O(1) hash | O(1) hash, adversarially controllable target | O(1) |
//! | Connection distribution over W shards, c connections, uniform hash | max load `c/W + Theta(sqrt((c log W)/W))` | O(c) on one shard with a degenerate or attacker-chosen 4-tuple hash | O(c) |
//! | Same, with work stealing after accept (`balanced` mode) | `c/W + o(c/W)` | `c/W + O(1)` task skew bounded by steal latency | O(c) |

#![deny(missing_docs)]

pub mod accept;
pub mod listener;
pub mod registry;

pub use accept::{AcceptConfig, AcceptOutcome, BoxFut, ConnHandler, MAX_BACKOFF_MS, accept_loop};
pub use listener::{ListenError, ListenerReport, ShardedListener};
pub use registry::{ConnGuard, ConnRegistry, RegistryStats};
