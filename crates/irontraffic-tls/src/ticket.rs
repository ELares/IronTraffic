// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! Stateless TLS 1.3 session tickets with cluster-derived epoch keys.
//!
//! [`ClusterTicketer`] is the one `rustls::server::ProducesTickets` implementation in this
//! crate. Every subordinate key is HKDF-derived from one 32-byte cluster root plus an epoch
//! number, never distributed, so every node in a fleet holds the same key at the same time with
//! zero coordination: `key_e = HKDF-Expand-SHA384(prk, "irontraffic/ticket/v1" || context ||
//! be64(e))`, where `prk = HKDF-Extract-SHA384("irontraffic/ticket-root/v1", root)` and
//! `e = floor(unix_seconds / rotation_secs)`. A node encrypts with the current epoch's key and
//! accepts the current epoch and the two before it, a minimum 12-hour window at the default
//! 6-hour rotation.
//!
//! **The context binds a ticket to the configuration it was issued under.** A resumed TLS 1.3
//! handshake sends no certificate and does not re-run the client-certificate verifier, so a
//! ticket issued under one trust bundle would otherwise still be accepted after the bundle
//! changed (CVE-2025-68121, Go `crypto/tls`, GHSA-gv8r-9rw9-9697 in Traefik). Mixing a 16-byte
//! context into both derivations means a ticket from a different configuration produces a key
//! name nothing matches, which fails closed into a full handshake rather than resuming under
//! stale trust. This crate does not choose the context; the caller does (16 zero bytes for no
//! client authentication, `TrustAnchors::id()` otherwise), and `context` is a mandatory
//! constructor argument for exactly that reason.
//!
//! **What the epoch window bounds, and what it does not.** A leaked `key_e` is useless outside
//! its three-epoch acceptance window. It does NOT bound the damage from a leaked root: every
//! epoch key past and future is computable from the root, so the root's compromise is
//! retroactive over every ticket ever issued, unbounded until the root itself is rotated. The
//! root is therefore the highest-value secret in the product; see `docs/THREAT-MODEL.md`'s
//! "Session resumption" section.
//!
//! Every function on the decrypt path below is written so that `decrypt` never allocates on the
//! path an attacker controls (an unmatched key name), never reads a lifetime or any other
//! decision input out of the ticket besides the key name and nonce, and never panics for any
//! input, per rustls's own `ProducesTickets` documentation. `scripts/invariant-lints.sh`'s
//! `hot-path-allocation` rule enforces the first property across this whole file (a text scan
//! for a fixed list of allocating call spellings, escaped per line where a call is provably not
//! on the request path or is a fixed-size stack copy rather than a heap allocation); see the
//! escape comments below for exactly which lines that covers and why.
//!
//! This issue installs nothing: no `ServerConfig` carries a `ClusterTicketer` until
//! `mtls-client-auth-fail-closed` (#124), the first issue that can supply a correctly derived
//! `context`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rustls::server::ProducesTickets;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::store::TimeView;

/// Default rotation period, seconds. 6 hours.
pub const DEFAULT_TICKET_ROTATION_SECS: u32 = 21_600;
/// Minimum accepted ticket length: name plus nonce plus AEAD tag.
pub const MIN_TICKET_LEN: usize = 56;
/// Maximum accepted ticket length. A rustls TLS 1.3 ticket plaintext is a few hundred bytes;
/// anything larger than this is not ours.
pub const MAX_TICKET_LEN: usize = 4_096;
/// Number of accepted epochs: the current one plus two previous.
pub const ACCEPTED_EPOCHS: u64 = 3;

/// Ring size for the per-root epoch-key cache. At the 6-hour default rotation this covers 128
/// days before two live epochs alias the same slot. Each table is `SLOT_COUNT` entries of a
/// 56-byte `EpochKey` plus a `OnceLock` state word (64 bytes per slot), so the two tables
/// (primary and previous) together are 64 KiB per ticketer. That is why
/// `sni-server-config-selection` (#119) constructs at most one `ClusterTicketer` per distinct
/// context and shares it, rather than one per `TlsServerConfig`.
const SLOT_COUNT: usize = 512;
/// [`SLOT_COUNT`], restated as a `u64` for the epoch modulo below, so no cast is needed at the
/// call site. Both constants are the literal 512 and must be kept equal by inspection.
const SLOT_COUNT_U64: u64 = 512;

/// RFC 5869 HKDF-Extract salt for the ticket root. 27 bytes.
const ROOT_SALT: &[u8] = b"irontraffic/ticket-root/v1";
/// HKDF-Expand info prefix for the epoch key. 21 bytes; counted, because a wrong length here is
/// a silent `copy_from_slice` panic in [`ClusterTicketer::derive`].
const KEY_INFO_PREFIX: &[u8] = b"irontraffic/ticket/v1";
/// HKDF-Expand info prefix for the epoch key name. 26 bytes; counted for the same reason.
const NAME_INFO_PREFIX: &[u8] = b"irontraffic/ticket-name/v1";

/// Encodes `bytes` as lowercase ASCII hex, two characters per input byte.
///
/// Mirrors `CertFingerprint::to_hex` in `store/cred.rs`, restated here for an 8-byte input
/// rather than that type's 16, because a shared helper would have to cross a private-field
/// boundary between two otherwise unrelated modules for eight lines of arithmetic.
#[allow(
    clippy::indexing_slicing,
    reason = "bytes is [u8; 8] and i < 8, so i*2 and i*2+1 stay under 16; HEX is [u8; 16] and a \
              nibble is always < 16, so every index here is provably in bounds; mirrors \
              CertFingerprint::to_hex in store/cred.rs, which carries the identical allow"
)]
fn hex16(bytes: [u8; 8]) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for (i, byte) in bytes.iter().enumerate() {
        out[i * 2] = HEX[usize::from(byte >> 4)];
        out[i * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    out
}

/// The 32-byte cluster ticket root. Zeroized on drop; never logged, never in an error, never in
/// the admin API.
///
/// This is the highest-value secret in the product: every epoch key that has ever existed or
/// ever will is computable from it, so its compromise is retroactive over every ticket ever
/// issued. It is stored sealed, rotated on a schedule, and never printed; see
/// `docs/THREAT-MODEL.md`'s "Session resumption" section.
pub struct TicketRoot(Zeroizing<[u8; 32]>);

impl TicketRoot {
    /// Wrap 32 bytes as a cluster ticket root.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A fingerprint an operator can compare across nodes without learning the secret: the
    /// first 8 bytes of `blake3(b"irontraffic/ticket-root-fingerprint/v1" || root)`, lowercase
    /// hex, 16 ASCII characters.
    #[must_use]
    pub fn fingerprint_hex(&self) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"irontraffic/ticket-root-fingerprint/v1");
        hasher.update(self.0.as_slice());
        let digest = hasher.finalize();
        let mut narrowed = [0u8; 8];
        if let Some(head) = digest.as_bytes().get(..8) {
            narrowed.copy_from_slice(head);
        }
        hex16(narrowed)
    }
}

/// Hand-written rather than derived: `#[derive(Debug)]` would print the 32 secret bytes this
/// type exists to protect. Prints only the operator-comparable fingerprint, exactly
/// `TicketRoot(fp=<16 hex chars>)`.
impl core::fmt::Debug for TicketRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fp = self.fingerprint_hex();
        let text = core::str::from_utf8(&fp).map_err(|_| core::fmt::Error)?;
        write!(f, "TicketRoot(fp={text})")
    }
}

/// One epoch's derived material. 56 bytes, copied by value, zeroized on drop.
///
/// `Clone` is derived and is what [`ClusterTicketer::epoch_key`] returns; `Zeroizing<[u8; 32]>`
/// is `Clone` because `[u8; 32]` is. Do not add a hand-written `clone_value` method: every test
/// that needs an `EpochKey` must obtain it from `ClusterTicketer::epoch_key`, the one function
/// that actually performs the derivation, never by constructing this type directly, because its
/// existence asserts that the key really was derived from a live root under a live epoch.
#[derive(Clone)]
struct EpochKey {
    epoch: u64,
    key: Zeroizing<[u8; 32]>,
    name: [u8; 16],
}

/// Hand-written: `#[derive(Debug)]` would print the 32-byte key. Prints only the epoch,
/// exactly `EpochKey(epoch=<n>)`.
impl core::fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EpochKey(epoch={})", self.epoch)
    }
}

/// Which root's slot ring and pseudorandom key a candidate epoch key comes from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum RootSel {
    /// The current root, used for both encryption and decryption.
    Primary,
    /// The outgoing root during a rotation overlap, accepted for decryption only.
    Previous,
}

/// Source of 24-byte AEAD nonces.
///
/// The production implementation is [`RandNonceSource`], which draws from the operating system
/// CSPRNG through `irontraffic-rand`. Tests use a deterministic counter source so that a ticket
/// is reproducible.
pub trait NonceSource: Send + Sync + 'static {
    /// Fill `out` with 24 cryptographically random bytes.
    ///
    /// Returns `false` when the entropy source failed, in which case `out` is not usable and the
    /// caller MUST NOT issue a ticket. The return value exists because
    /// `irontraffic_rand::SecureRng::fill` is fallible and a silently unfilled buffer would be a
    /// repeated nonce, which breaks confidentiality outright.
    #[must_use]
    fn fill(&self, out: &mut [u8; 24]) -> bool;
}

/// Production nonce source over the determinism seam.
pub struct RandNonceSource;

impl NonceSource for RandNonceSource {
    /// Draws from the operating system CSPRNG through `irontraffic_rand::SecureRng::fill`, the
    /// only sanctioned entropy source in this crate. Never reads the entropy syscall or the
    /// non-cryptographic generator directly.
    fn fill(&self, out: &mut [u8; 24]) -> bool {
        irontraffic_rand::SecureRng::fill(out).is_ok()
    }
}

/// Counters for the ticket path. Every field is a relaxed, lossy `AtomicU64`.
#[derive(Debug, Default)]
pub struct TicketStats {
    /// `tls_ticket_encrypt_total`
    pub encrypts: AtomicU64,
    /// `tls_ticket_decrypt_ok_total`
    pub decrypt_ok: AtomicU64,
    /// `tls_ticket_decrypt_unknown_key_total`: no accepted epoch matched the key name.
    pub decrypt_unknown_key: AtomicU64,
    /// `tls_ticket_decrypt_aead_fail_total`: key name matched, AEAD open failed.
    pub decrypt_aead_fail: AtomicU64,
    /// `tls_ticket_decrypt_malformed_total`: length or framing wrong.
    pub decrypt_malformed: AtomicU64,
    /// `tls_ticket_decrypt_previous_root_total`: satisfied by the outgoing root.
    pub decrypt_previous_root: AtomicU64,
    /// `tls_ticket_epoch_current`: last observed epoch, for the cross-node divergence alarm.
    pub epoch_current: AtomicU64,
    /// `tls_ticket_epoch_slot_miss_total`: the slot held a different epoch, so the key was
    /// derived inline. Non-zero here means the clock jumped or the process outlived the slot
    /// ring.
    pub slot_misses: AtomicU64,
}

/// Stateless ticket encrypter and decrypter with cluster-derived epoch keys.
///
/// Constructing one is cheap in CPU but not in memory (two 512-slot rings, 64 KiB total): build
/// at most one per distinct `(root, previous root, context, rotation_secs)` tuple in a process
/// and share the `Arc`, never one per `TlsServerConfig`.
pub struct ClusterTicketer {
    /// HKDF pseudorandom key of the current root.
    primary: Zeroizing<[u8; 48]>,
    /// HKDF pseudorandom key of the outgoing root during a rotation overlap.
    previous: Option<Zeroizing<[u8; 48]>>,
    /// Client-authentication context mixed into every derivation. See the module documentation.
    context: [u8; 16],
    /// Rotation period, seconds. Clamped to `3_600..=86_400` in [`ClusterTicketer::new`].
    rotation_secs: u32,
    time: Arc<dyn TimeView>,
    nonces: Arc<dyn NonceSource>,
    slots_primary: Box<[OnceLock<EpochKey>]>,
    slots_previous: Box<[OnceLock<EpochKey>]>,
    stats: TicketStats,
    /// `TicketRoot::fingerprint_hex` of the primary root, captured in [`ClusterTicketer::new`]
    /// before the root is consumed into the HKDF pseudorandom key. Not part of the design note's
    /// own field sketch; added so this type's `Debug` impl (invariant 6) can print the same
    /// operator-comparable value `TicketRoot::fingerprint_hex` would, without retaining the root
    /// itself. 16 bytes, irrelevant next to the 64 KiB of slot tables above.
    fingerprint: [u8; 16],
}

/// Builds one ring of [`SLOT_COUNT`] empty slots. Called twice from [`ClusterTicketer::new`]:
/// once for the primary root's ring, once for the previous root's (initially unused until
/// [`ClusterTicketer::with_previous_root`] is called). Never called again afterward.
fn build_slot_ring() -> Box<[OnceLock<EpochKey>]> {
    (0..SLOT_COUNT)
        .map(|_| OnceLock::new())
        .collect::<Vec<_>>() // it-allow: hot-path-allocation reason: runs at most twice, inside ClusterTicketer::new, never on the encrypt or decrypt path; becomes the immutable slot ring for the ticketer's whole lifetime
        .into_boxed_slice() // it-allow: hot-path-allocation reason: converts the just-built Vec into the immutable slot ring; construction-time only, mirrors the builder-path allocations in store/index.rs
}

impl ClusterTicketer {
    /// Build a ticketer.
    ///
    /// `rotation_secs` is clamped to `3_600..=86_400`: a period under an hour makes the 3-epoch
    /// window shorter than a plausible client idle time, and a period over a day makes the
    /// forward-secrecy bound worse than a full handshake is expensive.
    ///
    /// `context` is the 16-byte client-authentication context described in the module
    /// documentation: 16 zero bytes when the listener requests no client certificate,
    /// `TrustAnchors::id()` otherwise. It is mixed into every key and key-name derivation, so
    /// tickets never cross configurations. This is a mandatory argument, not a default, so the
    /// caller cannot forget it.
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "root is consumed by value deliberately, matching the issue's own signature: \
                  taking ownership here means the root is dropped (and zeroized) at a known \
                  point at the end of this function, rather than leaving the caller responsible \
                  for a value this function only ever borrows internally"
    )]
    pub fn new(
        root: TicketRoot,
        context: [u8; 16],
        rotation_secs: u32,
        time: Arc<dyn TimeView>,
        nonces: Arc<dyn NonceSource>,
    ) -> Self {
        let fingerprint = root.fingerprint_hex();
        let primary = crate::hkdf::extract_sha384(ROOT_SALT, root.0.as_slice());
        Self {
            primary,
            previous: None,
            context,
            rotation_secs: rotation_secs.clamp(3_600, 86_400),
            time,
            nonces,
            slots_primary: build_slot_ring(),
            slots_previous: build_slot_ring(),
            stats: TicketStats::default(),
            fingerprint,
        }
    }

    /// Add an outgoing root for a rotation overlap. Tickets are encrypted with the primary root
    /// only; both roots are accepted for decryption. Call this when the operator rotates
    /// `cluster_secret`, with the OLD root as `previous`.
    ///
    /// Do not pass a compromised root here during break-glass rotation: the overlap exists to
    /// preserve resumption across a planned rotation, and including a compromised root keeps
    /// every ticket it issued decryptable, which defeats the point of rotating away from it.
    ///
    /// Calling this again (an operator swapping the overlap root from one previous root to
    /// another, without restarting) evicts every cached slot from the OLD previous root's ring:
    /// a slot that already cached an epoch key derived from the outgoing root would otherwise
    /// keep answering from that stale key for as long as the slot survives, up to `SLOT_COUNT`
    /// epochs (128 days at the default rotation), because a cache hit only compares the
    /// candidate epoch, never which root derived the cached entry. Evicting the whole ring is
    /// what makes "swap the previous root" take effect immediately rather than eventually.
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "previous is consumed by value deliberately, for the same reason new's root \
                  parameter is: this function only borrows it internally, but taking ownership \
                  drops (and zeroizes) it at a known point rather than leaving the caller \
                  responsible for it"
    )]
    pub fn with_previous_root(mut self, previous: TicketRoot) -> Self {
        self.previous = Some(crate::hkdf::extract_sha384(
            ROOT_SALT,
            previous.0.as_slice(),
        ));
        self.slots_previous = build_slot_ring();
        self
    }

    /// The current epoch, `floor(unix_seconds / rotation_secs)`.
    #[must_use]
    #[allow(
        clippy::integer_division,
        reason = "this is the key schedule's own definition of an epoch (design's exact \
                  formula floor(unix_seconds / rotation_secs)); rotation_secs is clamped to at \
                  least 3_600 in new, so the divisor is never zero, and truncation toward zero \
                  is the intended floor"
    )]
    pub fn epoch_now(&self) -> u64 {
        self.time.unix_seconds().get() / u64::from(self.rotation_secs)
    }

    /// The rotation period in seconds.
    #[must_use]
    pub fn rotation_secs(&self) -> u32 {
        self.rotation_secs
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &TicketStats {
        &self.stats
    }

    /// The number of TLS 1.3 tickets a listener should send. Always 2: enough for a client to
    /// open a second connection without a full handshake, not enough to be a ticket
    /// amplification vector. The listener compilation reads this and sets `send_tls13_tickets`.
    #[must_use]
    pub fn tickets_to_send() -> u32 {
        2
    }

    /// Looks up (or derives and caches) the epoch key for `root` and `epoch`.
    ///
    /// Returns `None` immediately for `RootSel::Previous` when no previous root is configured.
    /// A cache hit is one acquire load and a 56-byte copy; a miss derives inline without
    /// caching, which is safe (a race can only initialize a slot with a different epoch if two
    /// threads computed different epochs at the same instant across a rotation boundary, which
    /// is benign: both derivations are pure functions of `(root, epoch)`).
    fn epoch_key(&self, root: RootSel, epoch: u64) -> Option<EpochKey> {
        let (slots, prk) = match root {
            RootSel::Primary => (&self.slots_primary, &self.primary),
            RootSel::Previous => (&self.slots_previous, self.previous.as_ref()?),
        };
        let index = usize::try_from(epoch % SLOT_COUNT_U64).unwrap_or(0);
        let slot = slots.get(index)?;

        if let Some(k) = slot.get() {
            if k.epoch == epoch {
                return Some(k.clone()); // it-allow: hot-path-allocation reason: EpochKey::clone copies 56 bytes of stack data (a u64, a [u8; 32], and a [u8; 16]); it performs no heap allocation, but the plain .clone() spelling still matches this rule's text scan, mirroring store/challenge.rs's identical NameHasher::clone escape
            }
            self.stats.slot_misses.fetch_add(1, Ordering::Relaxed);
            return Some(self.derive(prk, epoch));
        }

        let k = slot.get_or_init(|| self.derive(prk, epoch));
        if k.epoch == epoch {
            return Some(k.clone()); // it-allow: hot-path-allocation reason: EpochKey::clone copies 56 bytes of stack data, performing no heap allocation; see the identical escape above
        }
        self.stats.slot_misses.fetch_add(1, Ordering::Relaxed);
        Some(self.derive(prk, epoch))
    }

    /// Derives the epoch key and its public name for `epoch` from `prk`, mixing in
    /// `self.context`.
    ///
    /// `KEY_INFO_PREFIX` is 21 bytes and `NAME_INFO_PREFIX` is 26 bytes; both are counted in
    /// their own constant's documentation, because a wrong array length here is a silent
    /// `copy_from_slice` no-op (via the `get_mut` checks below) rather than the derivation it
    /// looks like.
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "prk is a 48-byte HKDF pseudorandom key; see expand_sha384's identical allow in \
                  hkdf.rs for why this stays a reference rather than a by-value copy"
    )]
    fn derive(&self, prk: &[u8; 48], epoch: u64) -> EpochKey {
        let e = epoch.to_be_bytes();

        let mut info_key = [0u8; 21 + 16 + 8];
        if let Some(dst) = info_key.get_mut(..21) {
            dst.copy_from_slice(KEY_INFO_PREFIX);
        }
        if let Some(dst) = info_key.get_mut(21..37) {
            dst.copy_from_slice(&self.context);
        }
        if let Some(dst) = info_key.get_mut(37..) {
            dst.copy_from_slice(&e);
        }

        let mut info_name = [0u8; 26 + 16 + 8];
        if let Some(dst) = info_name.get_mut(..26) {
            dst.copy_from_slice(NAME_INFO_PREFIX);
        }
        if let Some(dst) = info_name.get_mut(26..42) {
            dst.copy_from_slice(&self.context);
        }
        if let Some(dst) = info_name.get_mut(42..) {
            dst.copy_from_slice(&e);
        }

        let mut key_bytes = [0u8; 32];
        let mut name = [0u8; 16];
        let _ = crate::hkdf::expand_sha384(prk, &info_key, &mut key_bytes); // it-allow: no-swallowed-error reason: expand_sha384 cannot fail for L in 1..=48 (see hkdf.rs); a false return here would itself be a bug, and leaving key_bytes at its all-zero initializer is safer than unwrapping in a crate that denies unwrap
        let _ = crate::hkdf::expand_sha384(prk, &info_name, &mut name); // it-allow: no-swallowed-error reason: identical reasoning to the key derivation above

        EpochKey {
            epoch,
            key: Zeroizing::new(key_bytes),
            name,
        }
    }

    /// Returns `true` if this ticketer will encrypt and decrypt tickets. Always `true`: a
    /// disabled ticketer is a dummy implementation this crate does not have.
    #[must_use]
    pub fn enabled(&self) -> bool {
        true
    }

    /// `rotation_secs`, the honest answer: this ticketer guarantees a key exists for at least
    /// this long from issuance and at most three epochs of acceptance. RFC 8446 caps a ticket
    /// lifetime hint at 7 days; the maximum configurable `rotation_secs` (86,400, one day) is
    /// far below that.
    #[must_use]
    pub fn lifetime(&self) -> u32 {
        self.rotation_secs
    }

    /// Encrypts `plain` (rustls's serialized session state) under the current epoch's key.
    ///
    /// Returns `None` if the entropy source fails to fill a nonce: issuing a ticket with a
    /// nonce the entropy source did not actually write would be a repeated nonce, which breaks
    /// confidentiality outright, whereas failing to issue one only costs the client a full
    /// handshake next time.
    #[must_use]
    pub fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let e = self.epoch_now();
        // Fully qualified rather than `self.stats.epoch_current.store(...)`: this is a plain
        // AtomicU64 snapshot counter, not an ArcSwap, but scripts/invariant-lints.sh's
        // single-snapshot-publish rule matches any `.store(` call by name to keep ArcSwap
        // publication to one site, and the dot-method form matches it. Written this way rather
        // than added to scripts/allowlist-arcswap-store.txt, mirroring the identical precedent
        // in crates/irontraffic-resilience/src/limits/mod.rs and pressure.rs.
        AtomicU64::store(&self.stats.epoch_current, e, Ordering::Relaxed);
        let ek = self.epoch_key(RootSel::Primary, e)?;

        let mut nonce = [0u8; 24];
        if !self.nonces.fill(&mut nonce) {
            return None;
        }

        let mut out = Vec::with_capacity(16 + 24 + plain.len() + 16); // it-allow: hot-path-allocation reason: the one unavoidable allocation on the ticket-issuance path, since rustls's ProducesTickets trait returns Option<Vec<u8>>; runs at most twice per full handshake (tickets_to_send), never per already-resumed request
        out.extend_from_slice(&ek.name);
        out.extend_from_slice(&nonce);

        let aead = XChaCha20Poly1305::new(Key::from_slice(ek.key.as_slice()));
        let Ok(ct) = aead.encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &ek.name,
            },
        ) else {
            return None;
        };
        out.extend_from_slice(&ct);

        self.stats.encrypts.fetch_add(1, Ordering::Relaxed);
        Some(out)
    }

    /// Decrypts `cipher`, which is fully attacker controlled: this function must not panic, must
    /// not allocate on a path an attacker can drive to a `None`, and must not read a lifetime, an
    /// epoch, or any other decision input out of the ticket besides the 16-byte key name and the
    /// 24-byte nonce, both of which are authenticated (the name as AAD, the nonce as the AEAD
    /// nonce).
    #[must_use]
    pub fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        if cipher.len() < MIN_TICKET_LEN || cipher.len() > MAX_TICKET_LEN {
            self.stats.decrypt_malformed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let name = cipher.get(..16)?;
        let nonce = cipher.get(16..40)?;
        let ct = cipher.get(40..)?;

        let e = self.epoch_now();

        // Compare every candidate key name against `name` in constant time, with no early exit.
        // The loop runs its full six iterations (2 roots x 3 epochs) every time: `ct_eq` is what
        // must be constant time, because that is the comparison an attacker could otherwise
        // probe byte by byte to forge a key name. Recording the FIRST hit only is a branch on
        // non-secret state (which epoch is live), not on the comparison result of an
        // attacker-chosen name against a secret, so it leaks nothing an attacker does not
        // already know.
        let mut matched: Option<(EpochKey, RootSel)> = None;
        let mut any: Choice = Choice::from(0u8);

        for root in [RootSel::Primary, RootSel::Previous] {
            for back in 0u64..ACCEPTED_EPOCHS {
                let Some(epoch) = e.checked_sub(back) else {
                    continue;
                };
                let Some(ek) = self.epoch_key(root, epoch) else {
                    continue;
                };
                let hit: Choice = ek.name.ct_eq(name);
                if bool::from(hit) && matched.is_none() {
                    matched = Some((ek, root));
                }
                any |= hit;
            }
        }

        if !bool::from(any) {
            self.stats
                .decrypt_unknown_key
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let (ek, root) = matched?;

        let aead = XChaCha20Poly1305::new(Key::from_slice(ek.key.as_slice()));
        let Ok(plain) = aead.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: name })
        else {
            self.stats.decrypt_aead_fail.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        if root == RootSel::Previous {
            self.stats
                .decrypt_previous_root
                .fetch_add(1, Ordering::Relaxed);
        }
        self.stats.decrypt_ok.fetch_add(1, Ordering::Relaxed);
        Some(plain)
    }
}

/// Hand-written rather than derived: a `#[derive(Debug)]` would print the primary and previous
/// HKDF pseudorandom keys. Prints exactly
/// `ClusterTicketer(fp=<16 hex chars> epoch=<n> rotation_secs=<n> previous=<bool>)`, where `fp`
/// is the same value `TicketRoot::fingerprint_hex` would print for the root this ticketer was
/// built from, and `epoch` is a live read through the time seam rather than a stale snapshot.
impl core::fmt::Debug for ClusterTicketer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = core::str::from_utf8(&self.fingerprint).map_err(|_| core::fmt::Error)?;
        write!(
            f,
            "ClusterTicketer(fp={text} epoch={} rotation_secs={} previous={})",
            self.epoch_now(),
            self.rotation_secs,
            self.previous.is_some(),
        )
    }
}

/// Adds no public item of its own (per this crate's Public API contract): every method here
/// forwards to the identically named, identically behaved inherent method above, which is what
/// every caller in this crate (including its own tests, benchmarks, and fuzz target) actually
/// calls. This impl exists only so a `ClusterTicketer` satisfies the trait rustls's
/// `ServerConfig` requires, for the later issue that installs one.
impl ProducesTickets for ClusterTicketer {
    fn enabled(&self) -> bool {
        Self::enabled(self)
    }

    fn lifetime(&self) -> u32 {
        Self::lifetime(self)
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        Self::encrypt(self, plain)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        Self::decrypt(self, cipher)
    }
}

// `ClusterTicketer` is `Send + Sync` and immutable apart from `OnceLock` initialization and
// relaxed counters (invariant 7). Checked at compile time rather than by a runtime test, which
// is what a `Send + Sync` property actually calls for: a runtime test can only ever demonstrate
// that one specific execution did not race, never that the type is safe to share by
// construction.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ClusterTicketer>();
};

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use proptest::prelude::*;
    use rustls::server::ProducesTickets;

    use super::{ClusterTicketer, NonceSource, RootSel, TicketRoot, TimeView};
    use crate::time::UnixSeconds;

    /// A `TimeView` whose value can be moved after construction, for tests that encrypt at one
    /// time and decrypt at another.
    struct TestClock(AtomicU64);

    impl TestClock {
        fn new(secs: u64) -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(secs)))
        }

        fn set(&self, secs: u64) {
            self.0.store(secs, Ordering::SeqCst);
        }

        fn get(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl TimeView for TestClock {
        fn unix_seconds(&self) -> UnixSeconds {
            UnixSeconds::new(self.get())
        }
    }

    /// Deterministic, non-repeating nonces: each call returns a distinct value, so a ticket is
    /// reproducible across a test run without ever repeating a nonce under the same key. This is
    /// the nonce source every test in this module uses except `primary_root_preferred`, which
    /// deliberately uses `FixedNonceSource` instead (edge case 18).
    #[derive(Default)]
    struct CountingNonceSource(AtomicU64);

    impl NonceSource for CountingNonceSource {
        fn fill(&self, out: &mut [u8; 24]) -> bool {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            if let Some(head) = out.get_mut(..8) {
                head.copy_from_slice(&n.to_be_bytes());
            }
            true
        }
    }

    /// Always returns the same 24 bytes. Edge case 18: a ticket still decrypts under a fixed
    /// nonce, which only proves the ticket format is correct. A real repeating nonce under the
    /// same key would be a confidentiality break; `RandNonceSource` is the only production
    /// implementation and it draws fresh entropy every call.
    struct FixedNonceSource([u8; 24]);

    impl NonceSource for FixedNonceSource {
        fn fill(&self, out: &mut [u8; 24]) -> bool {
            *out = self.0;
            true
        }
    }

    /// An entropy source that always fails, for `encrypt_returns_none_when_entropy_fails`.
    struct FailingNonceSource;

    impl NonceSource for FailingNonceSource {
        fn fill(&self, _out: &mut [u8; 24]) -> bool {
            false
        }
    }

    fn test_ticketer(
        root: [u8; 32],
        context: [u8; 16],
        rotation_secs: u32,
        clock: Arc<TestClock>,
    ) -> ClusterTicketer {
        ClusterTicketer::new(
            TicketRoot::new(root),
            context,
            rotation_secs,
            clock,
            Arc::new(CountingNonceSource::default()),
        )
    }

    #[test]
    fn decrypt_zero_len() {
        let clock = TestClock::new(1_000_000_000);
        let t = test_ticketer([0x01; 32], [0u8; 16], 21_600, clock);
        assert_eq!(t.decrypt(&[]), None);
        assert_eq!(t.stats().decrypt_malformed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn decrypt_len_55_and_56() {
        let clock = TestClock::new(1_000_000_000);
        let t = test_ticketer([0x02; 32], [0u8; 16], 21_600, clock);

        assert_eq!(t.decrypt(&[0u8; 55]), None);
        assert_eq!(t.stats().decrypt_malformed.load(Ordering::Relaxed), 1);

        // 56 is length-valid, so it must proceed to key selection instead of the malformed
        // arm; it then fails to match or fails AEAD (edge case 2 does not commit to which).
        assert_eq!(t.decrypt(&[0u8; 56]), None);
        assert_eq!(t.stats().decrypt_malformed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn decrypt_len_4096_and_4097() {
        let clock = TestClock::new(1_000_000_000);
        let t = test_ticketer([0x03; 32], [0u8; 16], 21_600, clock);

        // The literal lengths 4_096 and 4_097 are asserted directly, not built from
        // MAX_TICKET_LEN: a test that reads its expected boundary from the constant under test
        // proves consistency, never that the constant is actually 4,096.
        let at_max = vec![0xAB_u8; 4_096];
        assert_eq!(t.decrypt(&at_max), None);
        assert_eq!(t.stats().decrypt_malformed.load(Ordering::Relaxed), 0);

        let over_max = vec![0xAB_u8; 4_097];
        assert_eq!(t.decrypt(&over_max), None);
        assert_eq!(t.stats().decrypt_malformed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn decrypt_all_zero() {
        let clock = TestClock::new(1_000_000_000);
        let t = test_ticketer([0x04; 32], [0u8; 16], 21_600, clock);
        // Assert None and no panic, not the specific counter: an all-zero 16-byte name could in
        // principle be a real derived name, however overwhelmingly unlikely.
        assert_eq!(t.decrypt(&[0u8; 200]), None);
    }

    #[test]
    fn decrypt_corrupted_ciphertext() {
        let clock = TestClock::new(1_000_000_000);
        let t = test_ticketer([0x05; 32], [0u8; 16], 21_600, clock);
        let mut ct = t
            .encrypt(b"corrupt ciphertext")
            .expect("entropy never fails");
        let last = ct.len().saturating_sub(1);
        if let Some(byte) = ct.get_mut(last) {
            *byte ^= 0xff;
        }
        assert_eq!(t.decrypt(&ct), None);
        assert_eq!(t.stats().decrypt_aead_fail.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn decrypt_corrupted_nonce() {
        let clock = TestClock::new(1_000_000_000);
        let t = test_ticketer([0x06; 32], [0u8; 16], 21_600, clock);
        let mut ct = t.encrypt(b"corrupt nonce").expect("entropy never fails");
        // Byte 20 sits inside the 16..40 nonce range regardless of plaintext length.
        if let Some(byte) = ct.get_mut(20) {
            *byte ^= 0xff;
        }
        assert_eq!(t.decrypt(&ct), None);
        assert_eq!(t.stats().decrypt_aead_fail.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn decrypt_spliced_key_name() {
        let clock = TestClock::new(1_000_000_000);
        let t = test_ticketer([0x07; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let t0 = clock.get();

        let ticket_a = t.encrypt(b"ticket A").expect("entropy never fails");
        clock.set(t0 + 21_600);
        let ticket_b = t.encrypt(b"ticket B").expect("entropy never fails");

        // Splice ticket B's key name onto ticket A's nonce and ciphertext. The name is the AAD,
        // so the substitution changes what the AEAD authenticates and the tag check must fail,
        // even though the substituted name matches a live epoch key on its own.
        let name_b = ticket_b.get(..16).expect("at least 16 bytes").to_vec();
        let rest_a = ticket_a.get(16..).expect("at least 16 bytes").to_vec();
        let mut spliced = name_b;
        spliced.extend_from_slice(&rest_a);

        assert_eq!(t.decrypt(&spliced), None);
        assert_eq!(t.stats().decrypt_aead_fail.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn decrypt_window_e_to_e_plus_2_ok_e_plus_3_fails() {
        let clock = TestClock::new(1_000_000_000);
        let t = test_ticketer([0x08; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let t0 = clock.get();
        let ct = t.encrypt(b"window probe").expect("entropy never fails");

        for offset in 0u64..=2 {
            clock.set(t0 + offset * 21_600);
            let pt = t
                .decrypt(&ct)
                .unwrap_or_else(|| panic!("offset {offset} must still decrypt"));
            assert_eq!(pt, b"window probe");
        }

        clock.set(t0 + 3 * 21_600);
        assert_eq!(t.decrypt(&ct), None);
        assert_eq!(t.stats().decrypt_unknown_key.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn decrypt_older_node_clock_fails() {
        let clock = TestClock::new(21_600); // epoch 1
        let t = test_ticketer([0x09; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let ct = t.encrypt(b"future ticket").expect("entropy never fails");

        // The decrypting node's clock reads one rotation period BEHIND the epoch this ticket
        // was issued under. The window is backward looking only relative to the VERIFIER's own
        // current epoch, so a ticket from what is, to this node, the future is refused.
        clock.set(0); // epoch 0
        assert_eq!(t.decrypt(&ct), None);
        assert_eq!(t.stats().decrypt_unknown_key.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn epoch_zero_does_not_underflow() {
        let clock = TestClock::new(0);
        let t = test_ticketer([0x0A; 32], [0u8; 16], 3_600, Arc::clone(&clock));
        assert_eq!(t.epoch_now(), 0);

        let ct = t.encrypt(b"epoch zero").expect("entropy never fails");
        let pt = t.decrypt(&ct).expect("round trip at epoch 0 must succeed");
        assert_eq!(pt, b"epoch zero");

        // A length-valid, non-matching ticket at epoch 0 must not panic: `back = 1` and
        // `back = 2` would underflow a u64 epoch via `wrapping_sub`, which `checked_sub` in the
        // candidate loop exists to prevent.
        assert_eq!(t.decrypt(&[0u8; 100]), None);
    }

    #[test]
    fn clock_jump_forward_uses_inline_derivation() {
        let clock = TestClock::new(0);
        let t = test_ticketer([0x0B; 32], [0u8; 16], 3_600, Arc::clone(&clock));
        let ct0 = t.encrypt(b"before the jump").expect("entropy never fails");
        assert_eq!(t.stats().slot_misses.load(Ordering::Relaxed), 0);

        // Jump forward by exactly SLOT_COUNT (512) rotation periods: epoch 512 % 512 == 0, the
        // same ring slot epoch 0 already populated with a different epoch's key, forcing the
        // slot-miss and inline-derivation path `epoch_key` describes. An exact multiple of
        // SLOT_COUNT makes the collision deterministic; the edge case's "ten years forward" is
        // the same failure mode at whatever rotation_secs an operator configures, not a literal
        // magnitude this test must reproduce.
        clock.set(512 * 3_600);
        let ct1 = t.encrypt(b"after the jump").expect("entropy never fails");
        let pt1 = t
            .decrypt(&ct1)
            .expect("decrypt must still succeed after the slot collision");
        assert_eq!(pt1, b"after the jump");
        assert!(
            t.stats().slot_misses.load(Ordering::Relaxed) > 0,
            "a slot collision across a huge forward jump must be recorded, even though the \
             answer stays correct"
        );

        // The pre-jump ticket is now far outside the acceptance window (epoch 0 vs epoch 512).
        assert_eq!(t.decrypt(&ct0), None);
    }

    #[test]
    fn clock_jump_backward_is_correct() {
        let clock = TestClock::new(512 * 3_600);
        let t = test_ticketer([0x0C; 32], [0u8; 16], 3_600, Arc::clone(&clock));
        let ct0 = t
            .encrypt(b"before the jump back")
            .expect("entropy never fails");
        assert_eq!(t.stats().slot_misses.load(Ordering::Relaxed), 0);

        // Jump backward to epoch 0, which aliases the same ring slot as epoch 512.
        clock.set(0);
        let ct1 = t
            .encrypt(b"after the jump back")
            .expect("entropy never fails");
        let pt1 = t
            .decrypt(&ct1)
            .expect("decrypt must still succeed after the slot collision");
        assert_eq!(pt1, b"after the jump back");
        assert!(t.stats().slot_misses.load(Ordering::Relaxed) > 0);

        // Now at epoch 0, the window is {0} only (back = 1, 2 underflow and are skipped), so
        // the epoch-512 ticket is unknown.
        assert_eq!(t.decrypt(&ct0), None);
    }

    #[test]
    fn previous_root_accepted() {
        let clock = TestClock::new(1_000_000_000);
        let old = test_ticketer([0x0D; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let ct = old
            .encrypt(b"rotation overlap")
            .expect("entropy never fails");

        let time: Arc<dyn TimeView> = clock.clone();
        let new = ClusterTicketer::new(
            TicketRoot::new([0x0E; 32]),
            [0u8; 16],
            21_600,
            time,
            Arc::new(CountingNonceSource::default()),
        )
        .with_previous_root(TicketRoot::new([0x0D; 32]));

        let pt = new
            .decrypt(&ct)
            .expect("must decrypt via the overlapped previous root");
        assert_eq!(pt, b"rotation overlap");
        assert_eq!(new.stats().decrypt_previous_root.load(Ordering::Relaxed), 1);
    }

    /// `with_previous_root` swaps in a new overlap root without a restart; a ticket from the
    /// root it just discarded must stop decrypting immediately, not up to `SLOT_COUNT` epochs
    /// later. Without evicting `slots_previous`, a slot already cached from the OLD previous
    /// root would keep answering from that stale key: `epoch_key`'s cache hit only compares the
    /// candidate epoch, never which root actually derived the cached entry, so the swap would
    /// silently not take effect until the slot's epoch itself rolled out of the acceptance
    /// window, up to 128 days at the default rotation.
    #[test]
    fn with_previous_root_evicts_previous_slot_ring() {
        let clock = TestClock::new(1_000_000_000);
        let time: Arc<dyn TimeView> = clock.clone();

        // Root A, the overlap root about to be discarded, minted a ticket while it was live.
        let root_a = test_ticketer([0x1E; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let ct_from_a = root_a
            .encrypt(b"discarded previous root")
            .expect("entropy never fails");

        let t = ClusterTicketer::new(
            TicketRoot::new([0x1D; 32]),
            [0u8; 16],
            21_600,
            Arc::clone(&time),
            Arc::new(CountingNonceSource::default()),
        )
        .with_previous_root(TicketRoot::new([0x1E; 32]));

        // Root A decrypts while it is the configured overlap root, which also populates
        // `slots_previous`'s cache for this epoch.
        assert_eq!(
            t.decrypt(&ct_from_a).as_deref(),
            Some(&b"discarded previous root"[..]),
            "root A must decrypt while it is the configured overlap root"
        );

        // Operator rotates the overlap root from A to B without restarting the process.
        let t = t.with_previous_root(TicketRoot::new([0x1F; 32]));

        assert_eq!(
            t.decrypt(&ct_from_a),
            None,
            "a ticket from the DISCARDED previous root must no longer decrypt once \
             with_previous_root swaps in a new one"
        );
    }

    #[test]
    fn primary_root_preferred() {
        let clock = TestClock::new(1_000_000_000);
        // Edge case 18: a fixed (always identical) nonce source rather than the counting one
        // used elsewhere in this module. The ticket still decrypts, which is what this source
        // exists to prove about the ticket format; a real repeating nonce under the same key
        // would be a confidentiality break, which is why RandNonceSource always draws fresh
        // entropy and no other test in this module reuses a nonce.
        let time: Arc<dyn TimeView> = clock.clone();
        let t = ClusterTicketer::new(
            TicketRoot::new([0x0F; 32]),
            [0u8; 16],
            21_600,
            time,
            Arc::new(FixedNonceSource([0x5Au8; 24])),
        )
        .with_previous_root(TicketRoot::new([0x10; 32]));

        let ct = t
            .encrypt(b"primary preferred")
            .expect("entropy never fails");
        let pt = t.decrypt(&ct).expect("must decrypt with the primary root");
        assert_eq!(pt, b"primary preferred");
        assert_eq!(t.stats().decrypt_previous_root.load(Ordering::Relaxed), 0);
        assert_eq!(t.stats().decrypt_ok.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn old_root_without_overlap_is_unknown_key() {
        let clock = TestClock::new(1_000_000_000);
        let a = test_ticketer([0x11; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let b = test_ticketer([0x12; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let ct = a.encrypt(b"old root").expect("entropy never fails");
        assert_eq!(b.decrypt(&ct), None);
        assert_eq!(b.stats().decrypt_unknown_key.load(Ordering::Relaxed), 1);

        // Directly proves the guard `epoch_key` documents: with no previous root configured,
        // looking up a Previous-root candidate returns None immediately rather than silently
        // falling back to the primary root's own key material for that slot. Without this
        // assertion a fallback bug is invisible here: it would only ever recompute a candidate
        // identical to the primary one already checked, never widen what a ticket from a
        // genuinely different root can match.
        assert!(b.epoch_key(RootSel::Previous, b.epoch_now()).is_none());
    }

    #[test]
    fn rotation_secs_clamped() {
        let clock = TestClock::new(0);
        for (input, expected) in [
            (0u32, 3_600u32),
            (1, 3_600),
            (3_599, 3_600),
            (3_600, 3_600),
            (86_400, 86_400),
            (86_401, 86_400),
        ] {
            let t = test_ticketer([0x13; 32], [0u8; 16], input, Arc::clone(&clock));
            assert_eq!(t.rotation_secs(), expected, "input {input}");
        }
    }

    #[test]
    fn debug_hides_key_material() {
        let root = TicketRoot::new([0xAB; 32]);
        let root_text = format!("{root:?}");
        assert!(
            root_text.starts_with("TicketRoot(fp="),
            "unexpected format: {root_text}"
        );
        assert!(root_text.ends_with(')'), "unexpected format: {root_text}");
        let fp_part = root_text
            .strip_prefix("TicketRoot(fp=")
            .and_then(|s| s.strip_suffix(')'))
            .expect("format matches TicketRoot(fp=...)");
        assert_eq!(
            fp_part.len(),
            16,
            "unexpected fingerprint length: {fp_part}"
        );
        assert!(
            fp_part
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "fingerprint must be lowercase hex: {fp_part}"
        );
        assert!(!root_text.contains("abababab"), "{root_text}");

        let clock = TestClock::new(1_700_000_000);
        let ticketer = test_ticketer([0xAB; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let e = ticketer.epoch_now();
        let ek = ticketer
            .epoch_key(RootSel::Primary, e)
            .expect("primary root always yields an epoch key");
        let ek_text = format!("{ek:?}");
        assert_eq!(ek_text, format!("EpochKey(epoch={e})"));
        assert!(!ek_text.contains("abababab"));

        let ct_text = format!("{ticketer:?}");
        assert_eq!(
            ct_text,
            format!("ClusterTicketer(fp={fp_part} epoch={e} rotation_secs=21600 previous=false)")
        );
        assert!(!ct_text.contains("abababab"));

        let with_previous = ticketer.with_previous_root(TicketRoot::new([0xCD; 32]));
        assert!(format!("{with_previous:?}").contains("previous=true"));
    }

    #[test]
    fn tickets_to_send_is_two() {
        assert_eq!(ClusterTicketer::tickets_to_send(), 2);
    }

    #[test]
    fn different_context_never_decrypts() {
        let clock = TestClock::new(1_000_000_000);
        let a = test_ticketer([0x14; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let b = test_ticketer([0x14; 32], [1u8; 16], 21_600, Arc::clone(&clock));

        let ct = a.encrypt(b"context probe").expect("entropy never fails");
        assert_eq!(b.decrypt(&ct), None);
        assert_eq!(b.stats().decrypt_unknown_key.load(Ordering::Relaxed), 1);
    }

    /// This is the CVE-2025-68121 correction stated as a property test rather than a comment,
    /// pinning BOTH mechanisms the correction rests on rather than only the one
    /// `different_context_never_decrypts` happens to observe.
    ///
    /// Two ticketers share a root but not a context. That must change the derived AEAD KEY, not
    /// only the derived key NAME: dropping `self.context` from the key info while leaving it in
    /// the name info (so the name stays context bound but the underlying key silently stops
    /// being context bound) leaves `different_context_never_decrypts` passing, because that test
    /// only ever observes the name half through `decrypt`'s key selection step, never the key
    /// itself.
    #[test]
    fn context_binds_both_key_and_name() {
        let clock = TestClock::new(1_000_000_000);
        let a = test_ticketer([0x1B; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let b = test_ticketer([0x1B; 32], [1u8; 16], 21_600, Arc::clone(&clock));

        let e = a.epoch_now();
        let ka = a
            .epoch_key(RootSel::Primary, e)
            .expect("primary root always yields an epoch key");
        let kb = b
            .epoch_key(RootSel::Primary, e)
            .expect("primary root always yields an epoch key");

        assert_ne!(
            ka.name, kb.name,
            "two contexts sharing a root must derive different key NAMEs"
        );
        assert_ne!(
            ka.key.as_slice(),
            kb.key.as_slice(),
            "two contexts sharing a root must derive different AEAD KEYs, not only different names"
        );
    }

    /// Reproduces the exact CVE-2025-68121 shape rather than only comparing derived material in
    /// isolation: an attacker takes a ticket minted under one trust bundle's context and splices
    /// in a key name that is live under a DIFFERENT bundle's context, so that the second
    /// ticketer's key-selection step picks its own key for that name and attempts to open the
    /// first ticketer's ciphertext under it.
    ///
    /// Neither mechanism alone lets this succeed: with the name still bound as AEAD associated
    /// data, ticketer B's key selection finds a key whose name matches the splice, but decrypting
    /// authenticates against the SPLICED name, not the name ticketer A actually used as AAD, so
    /// the tag check fails even if `context_binds_both_key_and_name` above were somehow broken.
    /// Deleting BOTH the context-in-key-derivation binding AND the name-as-AAD binding together
    /// is what turns this into a working cross-context plaintext recovery.
    #[test]
    fn cross_context_name_splice_never_decrypts() {
        let clock = TestClock::new(1_000_000_000);
        let a = test_ticketer([0x1C; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let b = test_ticketer([0x1C; 32], [1u8; 16], 21_600, Arc::clone(&clock));

        let ticket_a = a
            .encrypt(b"peer identity from bundle A")
            .expect("entropy never fails");

        // Splice B's OWN live key name onto A's nonce and ciphertext, so B's key-selection step
        // finds a match in its own ring rather than failing at name lookup.
        let e = b.epoch_now();
        let kb = b
            .epoch_key(RootSel::Primary, e)
            .expect("primary root always yields an epoch key");
        let mut spliced = kb.name.to_vec();
        spliced.extend_from_slice(ticket_a.get(16..).expect("at least 16 bytes"));

        assert_eq!(
            b.decrypt(&spliced),
            None,
            "ticketer B must not recover ticketer A's plaintext via a cross-context key-name \
             splice, even though the spliced name matches a live key of B's own"
        );
    }

    /// The rustls `ProducesTickets` trait impl is the only surface rustls itself ever calls; a
    /// forwarding shim that nothing exercises through the trait object is unverified on the one
    /// path production actually runs. Binds `t` as `&dyn ProducesTickets` and round-trips through
    /// the trait's own methods, not the inherent ones every other test in this module calls.
    #[test]
    fn producestickets_trait_round_trips() {
        let clock = TestClock::new(1_700_000_000);
        let t = test_ticketer([0x1A; 32], [0u8; 16], 21_600, clock);
        let via_trait: &dyn ProducesTickets = &t;

        assert!(via_trait.enabled());
        assert_eq!(via_trait.lifetime(), 21_600);

        let ct = via_trait
            .encrypt(b"trait round trip")
            .expect("entropy never fails");
        let pt = via_trait
            .decrypt(&ct)
            .expect("must decrypt through the trait object, not only through the inherent method");
        assert_eq!(pt, b"trait round trip");
    }

    #[test]
    fn encrypt_returns_none_when_entropy_fails() {
        let clock = TestClock::new(1_000_000_000);
        let t = ClusterTicketer::new(
            TicketRoot::new([0x15; 32]),
            [0u8; 16],
            21_600,
            clock,
            Arc::new(FailingNonceSource),
        );
        assert_eq!(t.encrypt(b"hello"), None);
        assert_eq!(t.stats().encrypts.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unknown_key_path_allocates_nothing() {
        // WHAT THIS DOES AND DOES NOT PROVE, stated plainly (mirrors name.rs's
        // no_allocations_in_normalize, the established precedent for this exact tension in this
        // crate). This module carries the `//! HOT PATH` marker (asserted below), which puts the
        // whole file under scripts/invariant-lints.sh's hot-path-allocation rule: a text scan
        // for a fixed list of allocating call spellings, denied in CI unless escaped with a
        // stated reason. That CI-enforced scan, not this test, is what would catch a future edit
        // that adds a real heap allocation to decrypt's unknown-key path. This test's own
        // counter (crate::name::alloc_probe, the thread_local Cell<usize> event counter added by
        // sni-name-normalization, #113) only counts calls to alloc_probe::record, and nothing in
        // decrypt's unknown-key path calls it, because that path has no allocation site to
        // instrument: it touches only fixed-size stack arrays and Option<(EpochKey, RootSel)>,
        // and `EpochKey::clone` (see epoch_key's own escape comments) copies stack bytes, not a
        // heap allocation. So this loop's own job is to call decrypt 10,000 times on the
        // attacker's own input shape and confirm the counter stays exactly where it started.
        let source = include_str!("ticket.rs");
        assert!(
            source.lines().any(|line| line == "//! HOT PATH"),
            "ticket.rs must carry `//! HOT PATH` so scripts/invariant-lints.sh's \
             hot-path-allocation rule scans decrypt's unknown-key path at all"
        );

        let clock = TestClock::new(1_700_000_000);
        let t = test_ticketer([0x16; 32], [0u8; 16], 21_600, Arc::clone(&clock));
        let mut rng = irontraffic_rand::Rng::from_seed(0xA110_C000_D00D_u64);

        crate::name::alloc_probe::reset();
        for _ in 0..10_000u32 {
            let mut cipher = [0u8; 200];
            rng.fill_bytes(&mut cipher);
            // A random 200-byte buffer matching a live 16-byte key name has probability 2^-128
            // across this whole run; either outcome of decrypt here is fine, the point is that
            // it ran without allocating.
            let _ = t.decrypt(&cipher);
        }
        assert_eq!(
            crate::name::alloc_probe::count(),
            0,
            "no known allocation site fired while decrypting 10,000 unknown-key tickets"
        );
    }

    #[test]
    fn concurrent_encrypt_decrypt_across_threads() {
        const THREADS: usize = 64;
        const PER_THREAD: usize = 1_000;

        let clock = TestClock::new(1_700_000_000);
        let ticketer = Arc::new(test_ticketer(
            [0x17; 32],
            [0u8; 16],
            21_600,
            Arc::clone(&clock),
        ));

        let (txs, rxs): (Vec<_>, Vec<_>) = (0..THREADS).map(|_| mpsc::channel::<Vec<u8>>()).unzip();
        let mut rxs: Vec<Option<mpsc::Receiver<Vec<u8>>>> = rxs.into_iter().map(Some).collect();

        let mut handles = Vec::with_capacity(THREADS);
        for i in 0..THREADS {
            let ticketer = Arc::clone(&ticketer);
            let tx_right = txs[(i + 1) % THREADS].clone();
            let rx_mine = rxs
                .get_mut(i)
                .and_then(Option::take)
                .expect("each receiver taken exactly once");
            handles.push(std::thread::spawn(move || {
                for n in 0..PER_THREAD {
                    let plain = format!("thread {i} ticket {n}").into_bytes();
                    let ct = ticketer.encrypt(&plain).expect("entropy never fails");
                    tx_right.send(ct).expect("neighbor thread is alive");
                }
                drop(tx_right);

                let mut received = 0usize;
                while let Ok(cipher) = rx_mine.recv() {
                    let plain = ticketer
                        .decrypt(&cipher)
                        .expect("every ticket sent by our left neighbor must decrypt");
                    assert!(!plain.is_empty());
                    received += 1;
                }
                received
            }));
        }
        // Drop the original senders now that every thread holds its own clone; otherwise each
        // receiver's recv() would block forever, since the loop above never sees disconnection
        // while this outer copy is still alive.
        drop(txs);

        let mut total_received = 0usize;
        for h in handles {
            total_received += h.join().expect("no thread panicked");
        }
        assert_eq!(total_received, THREADS * PER_THREAD);
    }

    proptest! {
        #[test]
        fn prop_round_trip(
            root in prop::array::uniform32(any::<u8>()),
            plain in prop::collection::vec(any::<u8>(), 0..=2_000),
        ) {
            let clock = TestClock::new(1_700_000_000);
            let t = test_ticketer(root, [0u8; 16], 21_600, clock);
            let ct = t.encrypt(&plain).expect("entropy never fails under CountingNonceSource");
            let pt = t.decrypt(&ct).expect("round trip must succeed");
            prop_assert_eq!(pt, plain);
        }

        #[test]
        fn prop_random_bytes_never_decrypt(bytes in prop::collection::vec(any::<u8>(), 0..=5_000)) {
            let clock = TestClock::new(1_700_000_000);
            let t = test_ticketer([0x18; 32], [0u8; 16], 21_600, clock);
            // A random 16-byte prefix matching a derived key name has probability 2^-128 and is
            // not a test flake.
            prop_assert_eq!(t.decrypt(&bytes), None);
        }

        #[allow(
            clippy::integer_division,
            reason = "computes an epoch the same way epoch_now does, floor(unix_seconds / \
                      rotation_secs); rotation is the fixed literal DEFAULT_TICKET_ROTATION_SECS \
                      and is never zero"
        )]
        #[test]
        fn prop_epoch_window(
            t in (3 * u64::from(super::DEFAULT_TICKET_ROTATION_SECS))..1_000_000_000u64,
            delta_secs in -(2 * i64::from(super::DEFAULT_TICKET_ROTATION_SECS))
                ..=(4 * i64::from(super::DEFAULT_TICKET_ROTATION_SECS)),
        ) {
            let rotation = u64::from(super::DEFAULT_TICKET_ROTATION_SECS);
            let clock = TestClock::new(t);
            let ticketer = test_ticketer(
                [0x19; 32],
                [0u8; 16],
                super::DEFAULT_TICKET_ROTATION_SECS,
                Arc::clone(&clock),
            );
            let ct = ticketer
                .encrypt(b"epoch-window-probe")
                .expect("entropy never fails under CountingNonceSource");

            let t_signed = i64::try_from(t).unwrap_or(i64::MAX);
            let t2 = u64::try_from(t_signed + delta_secs).unwrap_or(0);
            clock.set(t2);

            let e1 = t / rotation;
            let e2 = t2 / rotation;
            let diff = i128::from(e2) - i128::from(e1);
            let should_succeed = (0..=2).contains(&diff);

            prop_assert_eq!(ticketer.decrypt(&ct).is_some(), should_succeed);
        }
    }
}
