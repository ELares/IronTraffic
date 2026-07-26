// SPDX-License-Identifier: MIT OR Apache-2.0

//! Non-Linux platform probes: the honest answers for whatever a non-Linux
//! host cannot provide.
//!
//! `net.core.somaxconn` is a Linux sysctl; no other platform (macOS,
//! Windows, or anything else this crate compiles on) has an equivalent file
//! to read, so this module reports the absence directly rather than
//! guessing or touching the filesystem to find out. `SO_REUSEPORT`,
//! `SO_REUSEADDR` and `IPV6_V6ONLY` are still probed for real on every unix,
//! including macOS, by the shared `socket2`-based probes in `super`;
//! `splice` and `SCM_RIGHTS` are compile-time answers computed inline in
//! `Caps::probe` (`cfg!(target_os = "linux")` / `cfg!(unix)`). Neither needs
//! a platform-specific implementation, so this module is deliberately
//! narrow: it exists for the one capability that is unconditionally absent
//! here.

/// No non-Linux target has `/proc/sys/net/core/somaxconn` (or any equivalent
/// this crate knows how to read), so this reports `None` without touching
/// the filesystem. Absence is not an error: `bind_listener` still succeeds,
/// it just cannot report whether the kernel will clamp the backlog.
pub(super) fn read_somaxconn() -> Option<u32> {
    None
}
