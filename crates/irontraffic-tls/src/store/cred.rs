// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Credentials`: one loaded, validated certificate chain plus its private key.
//!
//! [`Credentials::load`] parses the leaf once, extracts every field the rest of the subsystem
//! needs (key type, validity, must-staple, SAN names, serial, issuer DN) so nothing downstream
//! ever parses X.509 again, and verifies that the supplied private key matches the leaf's
//! public key. That last check is mandatory and unconditional: a mismatched key must be
//! rejected here, at config-compile time, never discovered later as a handshake failure.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use x509_cert::Certificate;
use x509_cert::der::asn1::{AnyRef, ObjectIdentifier};
use x509_cert::der::{Decode, Encode, Tagged};

use super::arena::{ChainInterner, MAX_DER_BYTES};
use super::challenge::ChallengeError;
use crate::time::UnixSeconds;

/// Maximum chain depth (leaf plus intermediates) we will accept.
pub const MAX_CHAIN_DEPTH: usize = 10;
/// Maximum dNSName SANs on one leaf.
pub const MAX_SANS: usize = 100;
/// Maximum bytes in an attached OCSP staple. Matches the 64 KiB fetch cap in the future
/// OCSP-staple updater; enforced here too so that a bug in the fetcher cannot put an unbounded
/// blob into a value that is cloned per credential and sent on every handshake.
pub const MAX_STAPLE_BYTES: usize = 65_536;

/// Maximum bytes in one accepted `san_dns_names()` entry (RFC 1035 total-name length).
const MAX_SAN_BYTES: usize = 253;

/// `id-ecPublicKey`, RFC 5480 section 2.1.1.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` / `secp256r1` named curve, RFC 5480 section 2.1.1.1.
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1` named curve, RFC 5480 section 2.1.1.1.
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// `rsaEncryption`, RFC 3279.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `id-Ed25519`, RFC 8410 section 3.
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// `id-ce-subjectAltName`, RFC 5280 section 4.2.1.6.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
/// `id-pe-tlsfeature`, RFC 7633.
const OID_TLS_FEATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.24");
/// The `status_request` TLS feature value inside `id-pe-tlsfeature`.
const STATUS_REQUEST_FEATURE: i64 = 5;
/// The DER identifier octet of a `GeneralName` `dNSName` (`[2] IMPLICIT IA5String`): class
/// context-specific (`10`), primitive (`0`), tag number `2`.
const DNS_NAME_TAG: u8 = 0x82;

/// Key type of a credential, ordered by server preference. Lower is preferred.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u8)]
pub enum KeyType {
    /// ECDSA on NIST P-256, preference rank 1.
    EcdsaP256 = 1,
    /// ECDSA on NIST P-384, preference rank 2.
    EcdsaP384 = 2,
    /// RSA, preference rank 3.
    Rsa = 3,
    /// Ed25519, preference rank 4.
    Ed25519 = 4,
}

/// Why loading a credential failed. Operator-facing; never sent to a peer.
///
/// No variant carries the rustls error text, the key bytes, or a file path: an error that says
/// too precisely why a key failed to match can be as disclosing as the key itself. Every
/// caller gets only the closed set of reasons below.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CertError {
    /// The chain had no certificates.
    EmptyChain,
    /// The chain exceeded `MAX_CHAIN_DEPTH`.
    ChainTooDeep,
    /// A DER blob was zero bytes.
    EmptyDer,
    /// A DER blob exceeded `MAX_DER_BYTES`.
    DerTooLarge,
    /// The leaf certificate did not parse.
    LeafParse,
    /// `notAfter` was not after `notBefore`.
    InvalidValidity,
    /// The public key algorithm or curve is not one we serve.
    UnsupportedKeyType,
    /// The `id-pe-tlsfeature` extension was present but did not decode.
    MalformedTlsFeature,
    /// The leaf carried more than `MAX_SANS` dNSName entries.
    TooManySans,
    /// The private key did not parse, or did not match the leaf's public key.
    KeyMismatch,
    /// The interner is full.
    TooManyDistinctBlobs,
    /// `install_process_provider` has not run, so there is no key provider to parse the key
    /// with. A startup ordering bug, not a bad certificate.
    ProviderNotInstalled,
    /// Two distinct DER blobs hashed to the same interner bucket (a 2^64 birthday event).
    /// Refused outright rather than risking one chain silently borrowing another's
    /// intermediate; see `crate::store::arena`'s module docs for why this is the load-bearing
    /// safety check, not the hash itself.
    BlobHashCollision,
    /// A name failed validation.
    Name(crate::name::NameError),
    /// A wildcard name was malformed.
    Wildcard(crate::name::WildcardError),
    /// A wildcard's parent has fewer than 2 labels or is a listed public suffix.
    WildcardTooBroad,
    /// Three independent hash keys all produced a collision between two configured names.
    NameHashCollision,
    /// The index would exceed `MAX_NAME_ARENA_BYTES` or `MAX_INDEX_GROUPS`, so a `u32` offset or
    /// group index would truncate. Refusing to build is the only safe answer: a truncated index
    /// serves the wrong name's certificate.
    IndexTooLarge,
    /// A challenge-map operation failed. Carries the challenge error unchanged.
    Challenge(ChallengeError),
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CertError::EmptyChain => f.write_str("certificate chain is empty"),
            CertError::ChainTooDeep => f.write_str("certificate chain exceeds 10 certificates"),
            CertError::EmptyDer => f.write_str("a DER blob was zero bytes"),
            CertError::DerTooLarge => f.write_str("a DER blob exceeds 65536 bytes"),
            CertError::LeafParse => f.write_str("the leaf certificate did not parse as X.509 DER"),
            CertError::InvalidValidity => f.write_str("notAfter is not after notBefore"),
            CertError::UnsupportedKeyType => f.write_str(
                "public key algorithm or curve is not one of ECDSA P-256, ECDSA P-384, RSA, Ed25519",
            ),
            CertError::MalformedTlsFeature => {
                f.write_str("the id-pe-tlsfeature extension is present but did not decode")
            }
            CertError::TooManySans => f.write_str("the leaf carries more than 100 dNSName SANs"),
            CertError::KeyMismatch => {
                f.write_str("the private key did not parse or does not match the leaf public key")
            }
            CertError::TooManyDistinctBlobs => {
                f.write_str("the chain interner is at its distinct-blob limit")
            }
            CertError::ProviderNotInstalled => {
                f.write_str("no crypto provider is installed; install_process_provider must run first")
            }
            CertError::BlobHashCollision => f.write_str(
                "two different certificate chain blobs hashed to the same interner bucket",
            ),
            CertError::Name(e) => write!(f, "invalid certificate name: {e}"),
            CertError::Wildcard(e) => write!(f, "invalid wildcard name: {e}"),
            CertError::WildcardTooBroad => {
                f.write_str("wildcard parent has fewer than 2 labels or is a listed public suffix")
            }
            CertError::NameHashCollision => f.write_str(
                "three independent name-hash keys all collided; this indicates a bug",
            ),
            CertError::IndexTooLarge => f.write_str(
                "the certificate index exceeds its 1 GiB name arena or 16777216 group limit",
            ),
            CertError::Challenge(e) => write!(f, "challenge map error: {e}"),
        }
    }
}

impl std::error::Error for CertError {}

impl From<crate::name::NameError> for CertError {
    fn from(e: crate::name::NameError) -> Self {
        CertError::Name(e)
    }
}

impl From<crate::name::WildcardError> for CertError {
    fn from(e: crate::name::WildcardError) -> Self {
        CertError::Wildcard(e)
    }
}

impl From<ChallengeError> for CertError {
    fn from(e: ChallengeError) -> Self {
        CertError::Challenge(e)
    }
}

/// BLAKE3-256 of the leaf DER, truncated to 16 bytes. This is the stable identity of a
/// credential across reloads and is the value the admin API and logs report. Private key
/// material never appears anywhere; the fingerprint is what we show instead.
///
/// A 128-bit truncated digest has only a 2^64 birthday bound, so equal fingerprints are a
/// display and lookup convenience, never proof that two credentials are the same certificate
/// for a trust decision; compare [`Credentials::leaf_der`] for that.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CertFingerprint([u8; 16]);

impl CertFingerprint {
    /// Lowercase hex, 32 ASCII characters, no separators, no `0x` prefix. This is what logs,
    /// metrics and the admin API show. Allocation-free: the caller wraps the result with
    /// `core::str::from_utf8` when it needs a `&str`.
    ///
    /// `CertFingerprint([0x0a, 0xff, 0x00, ...]).to_hex()` starts with `b"0aff00"`.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "out is [u8; 32] and i < 16, HEX is [u8; 16] and the nibble is < 16, so every \
                  index is provably in bounds; the crate denies clippy::indexing_slicing"
    )]
    pub fn to_hex(self) -> [u8; 32] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 32];
        for (i, byte) in self.0.iter().enumerate() {
            out[i * 2] = HEX[usize::from(byte >> 4)];
            out[i * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        out
    }
}

/// The first 16 bytes of a 32-byte digest, defensively: `full` is always exactly 32 bytes in
/// practice (it comes straight from `blake3::hash`), but this reads through a checked slice
/// rather than indexing so that fact never has to be re-verified for this to stay memory safe.
fn truncate16(full: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Some(head) = full.get(..16) {
        out.copy_from_slice(head);
    }
    out
}

/// One loaded, validated certificate chain plus its private key, plus everything the rest of
/// the subsystem needs to know about it so that nothing parses X.509 twice.
///
/// `Credentials` implements neither `PartialEq` (there is no correct definition of "the same
/// credential" that does not either ignore the key or perform a cryptographic comparison) nor
/// a derived `Debug`. `Debug` is written by hand below instead of derived, specifically so it
/// can never recurse into `certified`, whose `key: Arc<dyn SigningKey>` is the private key
/// material this whole type exists to protect.
pub struct Credentials {
    certified: Arc<rustls::sign::CertifiedKey>,
    key_type: KeyType,
    fingerprint: CertFingerprint,
    not_before: UnixSeconds,
    not_after: UnixSeconds,
    must_staple: bool,
    san_dns_names: Box<[Box<str>]>,
    serial: Box<[u8]>,
    issuer_dn: Box<[u8]>,
}

/// Hand-written and redacted: this must never recurse into `certified`, whose `key` field is
/// the private key material this type protects, and whose own `Debug` impl is defined by
/// whichever crypto provider is installed, outside this crate's control. Every field printed
/// here is already public on the certificate itself; a `{:?}` anywhere upstream, on this type
/// alone or nested inside a future container, can never surface key material.
impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credentials")
            .field("fingerprint", &self.fingerprint)
            .field("key_type", &self.key_type)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("must_staple", &self.must_staple)
            .finish_non_exhaustive()
    }
}

/// The public key algorithm and, for EC keys, the named curve, read from the leaf's
/// `SubjectPublicKeyInfo`. `SigningKey::algorithm()` cannot answer this on its own: it reports
/// `RSA`, `ECDSA` or `ED25519` with no curve, so P-256 and P-384 would be indistinguishable.
fn key_type_of(leaf: &Certificate) -> Result<KeyType, CertError> {
    let algorithm = &leaf.tbs_certificate.subject_public_key_info.algorithm;
    if algorithm.oid == OID_RSA_ENCRYPTION {
        return Ok(KeyType::Rsa);
    }
    if algorithm.oid == OID_ED25519 {
        return Ok(KeyType::Ed25519);
    }
    if algorithm.oid == OID_EC_PUBLIC_KEY {
        let curve = algorithm
            .parameters
            .as_ref()
            .and_then(|params| params.decode_as::<ObjectIdentifier>().ok())
            .ok_or(CertError::UnsupportedKeyType)?;
        if curve == OID_SECP256R1 {
            return Ok(KeyType::EcdsaP256);
        }
        if curve == OID_SECP384R1 {
            return Ok(KeyType::EcdsaP384);
        }
        return Err(CertError::UnsupportedKeyType);
    }
    Err(CertError::UnsupportedKeyType)
}

/// Whether the leaf carries `id-pe-tlsfeature` with the `status_request` value.
///
/// A present-but-undecodable extension is `Err(MalformedTlsFeature)`, never silently treated
/// as absent: an unparseable must-staple extension must not be downgraded to "no must-staple".
fn must_staple_of(leaf: &Certificate) -> Result<bool, CertError> {
    let extensions = leaf.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
    let Some(ext) = extensions.iter().find(|e| e.extn_id == OID_TLS_FEATURE) else {
        return Ok(false);
    };
    let features = <Vec<i64> as Decode>::from_der(ext.extn_value.as_bytes())
        .map_err(|_| CertError::MalformedTlsFeature)?;
    Ok(features.contains(&STATUS_REQUEST_FEATURE))
}

/// Every `dNSName` SAN on the leaf, ASCII-lowercased and byte-filtered.
///
/// Every `GeneralName` is decoded as an opaque tag-plus-bytes `AnyRef` rather than through
/// x509-cert's typed `Ia5String`, because that typed decoder rejects any byte above `0x7F` at
/// the ASN.1 layer: a single hostile byte in one SAN would turn into a whole-certificate parse
/// failure instead of the silent per-SAN drop the byte filter below is required to perform.
/// [`filtered_dns_name`] is this module's own allowlist, applied to the raw, type-unvalidated
/// content bytes, so a NUL, a newline, a space, or any non-ASCII byte can never survive into a
/// name another subsystem compares against a hostname.
fn san_dns_names_of(leaf: &Certificate) -> Result<Box<[Box<str>]>, CertError> {
    let extensions = leaf.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
    let Some(ext) = extensions
        .iter()
        .find(|e| e.extn_id == OID_SUBJECT_ALT_NAME)
    else {
        return Ok(Vec::new().into_boxed_slice());
    };

    let general_names = <Vec<AnyRef<'_>> as Decode>::from_der(ext.extn_value.as_bytes())
        .map_err(|_| CertError::LeafParse)?;

    let dns_name_count = general_names
        .iter()
        .filter(|name| u8::from(name.tag()) == DNS_NAME_TAG)
        .count();
    if dns_name_count > MAX_SANS {
        return Err(CertError::TooManySans);
    }

    let mut out = Vec::with_capacity(dns_name_count);
    for name in &general_names {
        if u8::from(name.tag()) != DNS_NAME_TAG {
            continue;
        }
        if let Some(filtered) = filtered_dns_name(name.value()) {
            out.push(filtered);
        }
    }
    Ok(out.into_boxed_slice())
}

/// Lowercase and validate one candidate SAN's raw content bytes.
///
/// Returns `None` (drop the whole SAN, never repair it) unless every byte, after ASCII
/// lowercasing, is in `[a-z0-9.\-*]` and the result is non-empty and at most 253 bytes. This is
/// a byte allowlist, not a denylist, precisely so an embedded NUL, an embedded newline, a
/// space, or any byte above `0x7F` cannot survive into a value another subsystem compares
/// against a hostname.
fn filtered_dns_name(raw: &[u8]) -> Option<Box<str>> {
    if raw.is_empty() || raw.len() > MAX_SAN_BYTES {
        return None;
    }
    let mut out = vec![0u8; raw.len()];
    for (i, &b) in raw.iter().enumerate() {
        let lower = if b.is_ascii_uppercase() { b | 0x20 } else { b };
        if !matches!(lower, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*') {
            return None;
        }
        let slot = out.get_mut(i)?;
        *slot = lower;
    }
    core::str::from_utf8(&out).ok().map(Into::into)
}

impl Credentials {
    /// Parse, validate and load a chain and key.
    ///
    /// `chain_der[0]` is the leaf. Elements `1..` are interned. The private key is verified
    /// against the leaf's public key.
    ///
    /// # Errors
    /// Any `CertError`. A failure leaves the interner unchanged except for blobs already
    /// interned by earlier elements of this same chain, which is harmless because interning is
    /// content-addressed and idempotent.
    pub fn load(
        chain_der: &[&[u8]],
        key_der: &[u8],
        interner: &mut ChainInterner,
    ) -> Result<Self, CertError> {
        if chain_der.is_empty() {
            return Err(CertError::EmptyChain);
        }
        if chain_der.len() > MAX_CHAIN_DEPTH {
            return Err(CertError::ChainTooDeep);
        }
        for blob in chain_der {
            if blob.len() > MAX_DER_BYTES {
                return Err(CertError::DerTooLarge);
            }
        }

        let (leaf_bytes, rest) = chain_der.split_first().ok_or(CertError::EmptyChain)?;
        let leaf_bytes: &[u8] = leaf_bytes;
        let leaf = Certificate::from_der(leaf_bytes).map_err(|_| CertError::LeafParse)?;

        let validity = leaf.tbs_certificate.validity;
        let not_before = UnixSeconds::new(validity.not_before.to_unix_duration().as_secs());
        let not_after = UnixSeconds::new(validity.not_after.to_unix_duration().as_secs());
        if not_after <= not_before {
            return Err(CertError::InvalidValidity);
        }

        let key_type = key_type_of(&leaf)?;
        let must_staple = must_staple_of(&leaf)?;
        let san_dns_names = san_dns_names_of(&leaf)?;

        let serial = leaf
            .tbs_certificate
            .serial_number
            .as_bytes()
            .to_vec()
            .into_boxed_slice();
        let issuer_dn = Encode::to_der(&leaf.tbs_certificate.issuer)
            .map_err(|_| CertError::LeafParse)?
            .into_boxed_slice();

        let fingerprint = CertFingerprint(truncate16(blake3::hash(leaf_bytes).as_bytes()));

        let mut cert_chain: Vec<CertificateDer<'static>> = Vec::with_capacity(chain_der.len());
        cert_chain.push(CertificateDer::from(leaf_bytes.to_vec()));
        for blob in rest {
            cert_chain.push(CertificateDer::from(interner.intern(blob)?));
        }

        // PrivateKeyDer::try_from sniffs PKCS#8, SEC1 and PKCS#1 and yields a value borrowed
        // from `key_der`; clone_key() copies it to a PrivateKeyDer<'static>, the lifetime
        // from_der requires.
        let key = PrivateKeyDer::try_from(key_der)
            .map_err(|_| CertError::KeyMismatch)?
            .clone_key();
        // The pub(crate) accessor lives in the `provider` module itself
        // (`crate::provider::provider`), not at the crate root: `crate::provider` alone names
        // that module, not a function.
        let provider = crate::provider::provider().ok_or(CertError::ProviderNotInstalled)?;
        // Every error from both the key parse and from_der maps to KeyMismatch. The rustls
        // error text never reaches this value: it would go to a config-compile diagnostic at
        // most, never a message a peer or a metric label could observe.
        let certified = rustls::sign::CertifiedKey::from_der(cert_chain, key, provider)
            .map_err(|_| CertError::KeyMismatch)?;

        Ok(Self {
            certified: Arc::new(certified),
            key_type,
            fingerprint,
            not_before,
            not_after,
            must_staple,
            san_dns_names,
            serial,
            issuer_dn,
        })
    }

    /// Key type, used for credential selection order.
    #[must_use]
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Stable identity of this credential.
    #[must_use]
    pub fn fingerprint(&self) -> CertFingerprint {
        self.fingerprint
    }

    /// Leaf `notBefore`.
    #[must_use]
    pub fn not_before(&self) -> UnixSeconds {
        self.not_before
    }

    /// Leaf `notAfter`.
    #[must_use]
    pub fn not_after(&self) -> UnixSeconds {
        self.not_after
    }

    /// Whether the leaf carries `id-pe-tlsfeature` with `status_request`.
    #[must_use]
    pub fn must_staple(&self) -> bool {
        self.must_staple
    }

    /// The currently attached OCSP staple, if any.
    #[must_use]
    pub fn staple(&self) -> Option<&[u8]> {
        self.certified.ocsp.as_deref()
    }

    /// The leaf's dNSName SANs, ASCII-lowercased.
    #[must_use]
    pub fn san_dns_names(&self) -> &[Box<str>] {
        &self.san_dns_names
    }

    /// The leaf's serial number as raw DER integer bytes.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// The leaf's issuer DN as encoded DER.
    #[must_use]
    pub fn issuer_dn(&self) -> &[u8] {
        &self.issuer_dn
    }

    /// The leaf certificate DER.
    #[must_use]
    pub fn leaf_der(&self) -> &[u8] {
        self.certified
            .cert
            .first()
            .map_or(&[][..], CertificateDer::as_ref)
    }

    /// The issuing certificate's DER, that is `chain_der[1]`, or `None` for a leaf-only chain.
    /// The OCSP updater needs it to build a `CertID` and to verify a response signature.
    #[must_use]
    pub fn issuer_der(&self) -> Option<&[u8]> {
        self.certified.cert.get(1).map(CertificateDer::as_ref)
    }

    /// A copy of this credential with a different OCSP staple attached.
    ///
    /// A staple longer than `MAX_STAPLE_BYTES` is not attached: this behaves as if `None` had
    /// been passed, fail-closed, never an error. This is a rebuild-and-replace, never a
    /// mutation, so no reader can ever observe a torn staple.
    #[must_use]
    pub fn with_staple(&self, staple: Option<Arc<[u8]>>) -> Self {
        let ocsp = staple.and_then(|s| {
            if s.len() > MAX_STAPLE_BYTES {
                None
            } else {
                Some(s.to_vec())
            }
        });
        let certified = rustls::sign::CertifiedKey {
            cert: self.certified.cert.clone(),
            key: Arc::clone(&self.certified.key),
            ocsp,
        };
        Self {
            certified: Arc::new(certified),
            key_type: self.key_type,
            fingerprint: self.fingerprint,
            not_before: self.not_before,
            not_after: self.not_after,
            must_staple: self.must_staple,
            san_dns_names: self.san_dns_names.clone(),
            serial: self.serial.clone(),
            issuer_dn: self.issuer_dn.clone(),
        }
    }

    /// The rustls credential this value wraps, for the resolver to clone into its return value.
    ///
    /// `pub(crate)` because it names a rustls type and must not cross the crate facade. This
    /// module is deliberately inert on merge (see the module docs): nothing calls this yet, the
    /// same reason `crate::provider::provider` carries its own `dead_code` allow. The caller is
    /// the certificate index and resolver added by a later issue.
    #[allow(
        dead_code,
        reason = "called by the certificate index/resolver issue that consumes Credentials; \
                  that issue is not in the tree yet, so this accessor has no caller until it \
                  lands"
    )]
    pub(crate) fn certified(&self) -> &Arc<rustls::sign::CertifiedKey> {
        &self.certified
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Once};

    use x509_cert::Certificate;
    use x509_cert::der::{Decode, Encode};

    use super::{CertError, ChainInterner, Credentials, KeyType, MAX_SANS, MAX_STAPLE_BYTES};

    /// Installs the process crypto provider exactly once for this whole test binary.
    ///
    /// `Credentials::load`'s key-matching step needs a real installed
    /// `rustls::crypto::CryptoProvider`, and provider installation is process-global:
    /// whichever test in this crate's test binary gets there first wins the race, and every
    /// later call correctly reports `AlreadyInstalled`, which this helper treats as success
    /// too, since either outcome leaves a provider installed, which is all this module's tests
    /// need. This creates a cross-file test-ordering hazard against
    /// `crate::provider::tests::provider_lifecycle`'s own before-install assertions; see the
    /// filed defect issue referenced in this issue's implementation report.
    fn ensure_provider_installed() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or crate::provider::tests::provider_lifecycle's own call installs the process-wide provider; either outcome (Ok or AlreadyInstalled) leaves a provider installed, which is all this helper promises.
        });
    }

    /// Returns `(leaf_der, key_der)` for a self-signed leaf with the given SANs.
    fn gen_leaf(alg: &'static rcgen::SignatureAlgorithm, sans: &[&str]) -> (Vec<u8>, Vec<u8>) {
        let params =
            rcgen::CertificateParams::new(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                .expect("valid SANs");
        let key = rcgen::KeyPair::generate_for(alg).expect("keygen");
        let cert = params.self_signed(&key).expect("sign");
        (cert.der().to_vec(), key.serialize_der())
    }

    /// Pads a leaf certificate with a custom extension until its DER encoding is exactly
    /// `target_len` bytes.
    ///
    /// DER length grows monotonically with the extension's content size (more content never
    /// produces a shorter encoding), so this converges: measure, adjust the pad length by the
    /// exact shortfall or overshoot, and repeat. The only non-content growth is the occasional
    /// extra length-of-length byte at an encoding size threshold, which the overshoot branch
    /// absorbs on the next pass.
    fn gen_leaf_padded_to(target_len: usize) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut pad_len: usize = 0;
        for _ in 0..32 {
            let mut params = rcgen::CertificateParams::new(vec!["pad.example.com".to_owned()])
                .expect("valid SANs");
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 2, 3, 4, 5, 6, 7, 8],
                    vec![0u8; pad_len],
                ));
            let der = params.self_signed(&key).expect("sign").der().to_vec();
            match der.len().cmp(&target_len) {
                std::cmp::Ordering::Equal => return (der, key.serialize_der()),
                std::cmp::Ordering::Less => pad_len += target_len - der.len(),
                std::cmp::Ordering::Greater => {
                    let overshoot = der.len() - target_len;
                    assert!(pad_len > overshoot, "padding search cannot shrink further");
                    pad_len -= overshoot;
                }
            }
        }
        panic!("padding search for target_len={target_len} did not converge");
    }

    #[test]
    fn load_ecdsa_p256_leaf_only() {
        ensure_provider_installed();
        let (leaf, key) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["example.com"]);
        let mut interner = ChainInterner::new();
        let cred = Credentials::load(&[&leaf], &key, &mut interner).expect("valid leaf and key");
        assert_eq!(cred.key_type(), KeyType::EcdsaP256);
        assert!(!cred.must_staple());
        let sans: Vec<&str> = cred.san_dns_names().iter().map(AsRef::as_ref).collect();
        assert_eq!(sans, vec!["example.com"]);
        assert_eq!(cred.leaf_der(), leaf.as_slice());
        assert!(cred.issuer_der().is_none());

        // Cross-check serial() and issuer_dn() against an independent x509-cert parse of the
        // same original bytes, rather than only checking they are non-empty: a mutation that
        // replaces either accessor with some other non-empty constant must still be caught.
        let parsed = Certificate::from_der(&leaf).expect("leaf parses independently");
        assert_eq!(
            cred.serial(),
            parsed.tbs_certificate.serial_number.as_bytes()
        );
        let expected_issuer_dn =
            Encode::to_der(&parsed.tbs_certificate.issuer).expect("issuer DN encodes");
        assert_eq!(cred.issuer_dn(), expected_issuer_dn.as_slice());

        // The hand-written Debug impl must actually print something (a mutation that replaces
        // its body with a no-op `Ok(Default::default())` would make this the empty string) and
        // must never be a derive that could recurse into the private key inside `certified`.
        let debug_str = format!("{cred:?}");
        assert!(debug_str.contains("Credentials"));
        assert!(debug_str.contains("fingerprint"));
    }

    #[test]
    fn load_ecdsa_p384() {
        ensure_provider_installed();
        let (leaf, key) = gen_leaf(&rcgen::PKCS_ECDSA_P384_SHA384, &["example.com"]);
        let mut interner = ChainInterner::new();
        let cred = Credentials::load(&[&leaf], &key, &mut interner).expect("valid leaf and key");
        assert_eq!(cred.key_type(), KeyType::EcdsaP384);
    }

    #[test]
    fn load_rsa2048() {
        ensure_provider_installed();
        let (leaf, key) = gen_leaf(&rcgen::PKCS_RSA_SHA256, &["example.com"]);
        let mut interner = ChainInterner::new();
        let cred = Credentials::load(&[&leaf], &key, &mut interner).expect("valid leaf and key");
        assert_eq!(cred.key_type(), KeyType::Rsa);
    }

    #[test]
    fn load_ed25519() {
        ensure_provider_installed();
        let (leaf, key) = gen_leaf(&rcgen::PKCS_ED25519, &["example.com"]);
        let mut interner = ChainInterner::new();
        let cred = Credentials::load(&[&leaf], &key, &mut interner).expect("valid leaf and key");
        assert_eq!(cred.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn load_p521_rejected() {
        let leaf: &[u8] = include_bytes!("../../tests/fixtures/p521-leaf.der");
        let mut interner = ChainInterner::new();
        let result = Credentials::load(&[leaf], &[], &mut interner);
        assert!(matches!(result, Err(CertError::UnsupportedKeyType)));
    }

    #[test]
    fn load_key_mismatch_rejected() {
        ensure_provider_installed();
        let (leaf_a, _key_a) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["a.example.com"]);
        let (_leaf_b, key_b) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["b.example.com"]);
        let mut interner = ChainInterner::new();
        let result = Credentials::load(&[&leaf_a], &key_b, &mut interner);
        let err = result.expect_err("a mismatched key must be rejected");
        assert_eq!(err, CertError::KeyMismatch);
        assert_eq!(
            err.to_string(),
            "the private key did not parse or does not match the leaf public key"
        );
    }

    #[test]
    fn challenge_error_converts_and_displays() {
        // Goes through the real `?`-driven conversion path (`From<ChallengeError>`), not a
        // hand-built `CertError::Challenge(..)` literal on both sides of the assertion: `.into()`
        // is what a `?` in `store::builder`'s flush actually calls, so a mutation that dropped
        // the `From` impl (or mismatched its variant) would fail here rather than only fail to
        // compile something no test exercises.
        let challenge_err = super::ChallengeError::Full;
        let cert_err: CertError = challenge_err.into();
        assert_eq!(cert_err, CertError::Challenge(super::ChallengeError::Full));
        assert_eq!(
            cert_err.to_string(),
            "challenge map error: the TLS-ALPN-01 challenge map already holds 512 entries"
        );
    }

    #[test]
    fn load_empty_chain_rejected() {
        let mut interner = ChainInterner::new();
        let result = Credentials::load(&[], &[], &mut interner);
        let err = result.expect_err("an empty chain must be rejected");
        assert_eq!(err, CertError::EmptyChain);
        assert_eq!(err.to_string(), "certificate chain is empty");
    }

    #[test]
    fn load_chain_depth_10_ok_11_rejected() {
        ensure_provider_installed();
        let (leaf, key) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["example.com"]);
        let filler = vec![0xAAu8; 16];

        let mut interner = ChainInterner::new();
        let chain_10: Vec<&[u8]> = std::iter::once(leaf.as_slice())
            .chain(std::iter::repeat_n(filler.as_slice(), 9))
            .collect();
        assert_eq!(chain_10.len(), 10);
        assert!(Credentials::load(&chain_10, &key, &mut interner).is_ok());

        let mut interner_11 = ChainInterner::new();
        let chain_11: Vec<&[u8]> = std::iter::once(leaf.as_slice())
            .chain(std::iter::repeat_n(filler.as_slice(), 10))
            .collect();
        assert_eq!(chain_11.len(), 11);
        let result = Credentials::load(&chain_11, &key, &mut interner_11);
        assert!(matches!(result, Err(CertError::ChainTooDeep)));
    }

    #[test]
    fn load_der_65536_ok_65537_rejected() {
        ensure_provider_installed();
        let (leaf_65536, key) = gen_leaf_padded_to(65_536);
        assert_eq!(leaf_65536.len(), 65_536);
        let mut interner = ChainInterner::new();
        assert!(Credentials::load(&[&leaf_65536], &key, &mut interner).is_ok());

        let mut leaf_65537 = leaf_65536.clone();
        leaf_65537.push(0u8);
        assert_eq!(leaf_65537.len(), 65_537);
        let mut interner_2 = ChainInterner::new();
        let result = Credentials::load(&[&leaf_65537], &key, &mut interner_2);
        let err = result.expect_err("a blob over MAX_DER_BYTES must be rejected");
        assert_eq!(err, CertError::DerTooLarge);
        assert_eq!(err.to_string(), "a DER blob exceeds 65536 bytes");
    }

    #[test]
    fn load_truncated_leaf_rejected() {
        let (leaf, key) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["example.com"]);
        let truncated = leaf
            .get(..40)
            .expect("fixture leaf is longer than 40 bytes");
        let mut interner = ChainInterner::new();
        let result = Credentials::load(&[truncated], &key, &mut interner);
        assert!(matches!(result, Err(CertError::LeafParse)));
    }

    #[test]
    fn load_must_staple_true() {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut params =
            rcgen::CertificateParams::new(vec!["example.com".to_owned()]).expect("valid SANs");
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                vec![0x30, 0x03, 0x02, 0x01, 0x05],
            ));
        let leaf = params.self_signed(&key).expect("sign").der().to_vec();
        let mut interner = ChainInterner::new();
        let cred = Credentials::load(&[&leaf], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key");
        assert!(cred.must_staple());
    }

    #[test]
    fn load_must_staple_malformed_rejected() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut params =
            rcgen::CertificateParams::new(vec!["example.com".to_owned()]).expect("valid SANs");
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                vec![0x30, 0x01],
            ));
        let leaf = params.self_signed(&key).expect("sign").der().to_vec();
        let mut interner = ChainInterner::new();
        let result = Credentials::load(&[&leaf], &key.serialize_der(), &mut interner);
        assert!(matches!(result, Err(CertError::MalformedTlsFeature)));
    }

    #[test]
    fn load_expired_is_ok() {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut params =
            rcgen::CertificateParams::new(vec!["example.com".to_owned()]).expect("valid SANs");
        params.not_before = rcgen::date_time_ymd(2019, 1, 1);
        params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        let leaf = params.self_signed(&key).expect("sign").der().to_vec();
        let mut interner = ChainInterner::new();
        let cred = Credentials::load(&[&leaf], &key.serialize_der(), &mut interner)
            .expect("an already-expired certificate still loads");
        // 2020-01-01T00:00:00Z, a well-known Unix timestamp.
        assert_eq!(cred.not_after().get(), 1_577_836_800);
    }

    #[test]
    fn load_invalid_validity_rejected() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut params =
            rcgen::CertificateParams::new(vec!["example.com".to_owned()]).expect("valid SANs");
        params.not_before = rcgen::date_time_ymd(2025, 6, 1);
        params.not_after = rcgen::date_time_ymd(2025, 6, 2);
        let mut leaf = params.self_signed(&key).expect("sign").der().to_vec();

        // rcgen refuses to emit notAfter < notBefore, so patch the encoded UTCTime bytes
        // directly. Both dates fall inside the UTCTime range (RFC 5280: before 2050), so
        // notAfter is encoded as the fixed-width 13-byte ASCII string "YYMMDDHHMMSSZ", which is
        // overwritten in place with an earlier timestamp of the identical byte length. The
        // signature becomes invalid, which is fine: `load` never verifies the leaf's own
        // signature.
        let target = b"250602000000Z";
        let replacement = b"200101000000Z";
        let pos = leaf
            .windows(target.len())
            .position(|w| w == target)
            .expect("notAfter UTCTime bytes must appear in the generated DER");
        leaf[pos..pos + target.len()].copy_from_slice(replacement);

        let mut interner = ChainInterner::new();
        let result = Credentials::load(&[&leaf], &key.serialize_der(), &mut interner);
        assert!(matches!(result, Err(CertError::InvalidValidity)));
    }

    #[test]
    fn load_101_sans_rejected() {
        ensure_provider_installed();

        // The boundary itself, exactly MAX_SANS, must still be accepted.
        let sans_100: Vec<String> = (0..100).map(|i| format!("h{i}.example.com")).collect();
        let san_100_refs: Vec<&str> = sans_100.iter().map(String::as_str).collect();
        let (leaf_100, key_100) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &san_100_refs);
        let mut interner_100 = ChainInterner::new();
        let cred_100 = Credentials::load(&[&leaf_100], &key_100, &mut interner_100)
            .expect("exactly MAX_SANS dNSName entries must load");
        assert_eq!(cred_100.san_dns_names().len(), MAX_SANS);

        let sans: Vec<String> = (0..101).map(|i| format!("h{i}.example.com")).collect();
        let san_refs: Vec<&str> = sans.iter().map(String::as_str).collect();
        let (leaf, key) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &san_refs);
        let mut interner = ChainInterner::new();
        let result = Credentials::load(&[&leaf], &key, &mut interner);
        assert!(matches!(result, Err(CertError::TooManySans)));
    }

    #[test]
    fn with_staple_produces_new_value() {
        ensure_provider_installed();
        let (leaf, key) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["example.com"]);
        let mut interner = ChainInterner::new();
        let original =
            Credentials::load(&[&leaf], &key, &mut interner).expect("valid leaf and key");
        let staple_bytes: Arc<[u8]> = Arc::from(vec![1u8, 2, 3].as_slice());
        let stapled = original.with_staple(Some(staple_bytes));
        assert_eq!(original.staple(), None);
        assert_eq!(stapled.staple(), Some(&[1u8, 2, 3][..]));
        assert_eq!(original.fingerprint(), stapled.fingerprint());
    }

    #[test]
    fn fingerprint_is_leaf_content_hash() {
        ensure_provider_installed();
        let (leaf_a, key_a) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["a.example.com"]);
        let mut interner = ChainInterner::new();
        let cred_a1 =
            Credentials::load(&[&leaf_a], &key_a, &mut interner).expect("valid leaf and key");
        let cred_a2 =
            Credentials::load(&[&leaf_a], &key_a, &mut interner).expect("valid leaf and key");
        assert_eq!(cred_a1.fingerprint(), cred_a2.fingerprint());

        let (leaf_b, key_b) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["b.example.com"]);
        let cred_b =
            Credentials::load(&[&leaf_b], &key_b, &mut interner).expect("valid leaf and key");
        assert_ne!(cred_a1.fingerprint(), cred_b.fingerprint());

        // to_hex() independently cross-checked against blake3's own hex encoder over the same
        // 16 bytes: the fingerprint is BLAKE3-256 of the leaf DER truncated to 16 bytes, and
        // blake3's to_hex() of the full 32-byte digest starts with the hex of those same 16
        // bytes (2 hex characters per byte).
        let full_hex = blake3::hash(&leaf_a).to_hex();
        let expected_hex_16 = full_hex.as_str().get(..32).expect("32 hex chars");
        let actual_hex = cred_a1.fingerprint().to_hex();
        let actual_hex_str = core::str::from_utf8(&actual_hex).expect("to_hex is ASCII");
        assert_eq!(actual_hex_str, expected_hex_16);
    }

    #[test]
    fn intern_shared_intermediate_is_one_copy() {
        ensure_provider_installed();
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut ca_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid SANs");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_der = ca_params
            .self_signed(&ca_key)
            .expect("self sign ca")
            .der()
            .to_vec();
        let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);

        let leaf1_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let leaf1_params = rcgen::CertificateParams::new(vec!["leaf1.example.com".to_owned()])
            .expect("valid SANs");
        let leaf1_der = leaf1_params
            .signed_by(&leaf1_key, &issuer)
            .expect("sign leaf1")
            .der()
            .to_vec();

        let leaf2_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let leaf2_params = rcgen::CertificateParams::new(vec!["leaf2.example.com".to_owned()])
            .expect("valid SANs");
        let leaf2_der = leaf2_params
            .signed_by(&leaf2_key, &issuer)
            .expect("sign leaf2")
            .der()
            .to_vec();

        let mut interner = ChainInterner::new();
        let cred1 = Credentials::load(
            &[&leaf1_der, &ca_der],
            &leaf1_key.serialize_der(),
            &mut interner,
        )
        .expect("valid chain 1");
        let cred2 = Credentials::load(
            &[&leaf2_der, &ca_der],
            &leaf2_key.serialize_der(),
            &mut interner,
        )
        .expect("valid chain 2");

        assert_eq!(interner.blob_count(), 1);
        assert_eq!(interner.hits(), 1);
        let a = cred1.issuer_der().expect("chain 1 has an intermediate");
        let b = cred2.issuer_der().expect("chain 2 has an intermediate");
        assert_eq!(a.as_ptr(), b.as_ptr());
        // Both leaves were signed by the same CA, so their leaf-level issuer DN (read straight
        // from each leaf's own TBSCertificate, independent of the interner) must match too.
        assert_eq!(cred1.issuer_dn(), cred2.issuer_dn());
        assert_ne!(cred1.fingerprint(), cred2.fingerprint());
    }

    #[test]
    fn load_skips_sans_failing_the_byte_filter() {
        ensure_provider_installed();
        // A NUL (the classic "www.example.com\0.evil.com" confusion), a space, and a byte
        // above 0x7F: three separate corrupted-second-SAN certificates, one per byte under test.
        for bad_byte in [0x00u8, b' ', 0xffu8] {
            let placeholder = "placeholder.example.com";
            let (mut leaf, key) = gen_leaf(
                &rcgen::PKCS_ECDSA_P256_SHA256,
                &["good.example.com", placeholder],
            );
            let needle = placeholder.as_bytes();
            let pos = leaf
                .windows(needle.len())
                .position(|w| w == needle)
                .expect("placeholder SAN bytes must appear in the generated DER");
            // Flip a byte in the middle of the placeholder so the corrupted SAN keeps the exact
            // same encoded length; only which byte is corrupted matters for this test.
            #[allow(
                clippy::integer_division,
                reason = "picking an approximate midpoint byte to corrupt; truncation is fine"
            )]
            let mid = pos + needle.len() / 2;
            leaf[mid] = bad_byte;

            let mut interner = ChainInterner::new();
            let cred = Credentials::load(&[&leaf], &key, &mut interner)
                .expect("a corrupted SAN is skipped, not a load failure");
            let sans: Vec<&str> = cred.san_dns_names().iter().map(AsRef::as_ref).collect();
            assert_eq!(sans, vec!["good.example.com"]);
            for san in cred.san_dns_names() {
                assert!(!san.contains('\0'));
            }
        }

        // A SAN longer than 253 bytes is dropped for its length alone, independent of the byte
        // filter: every byte in it is otherwise a legal `[a-z]`.
        let long_san = "a".repeat(300);
        assert!(long_san.len() > 253);
        let (leaf_long, key_long) = gen_leaf(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &["good.example.com", &long_san],
        );
        let mut interner_long = ChainInterner::new();
        let cred_long = Credentials::load(&[&leaf_long], &key_long, &mut interner_long)
            .expect("an oversized SAN is skipped, not a load failure");
        let sans_long: Vec<&str> = cred_long
            .san_dns_names()
            .iter()
            .map(AsRef::as_ref)
            .collect();
        assert_eq!(sans_long, vec!["good.example.com"]);

        // An uppercase SAN must survive lowercased, not merely unrejected: this is the only
        // place any of these tests actually exercise the ASCII-lowercasing branch itself.
        let (leaf_upper, key_upper) =
            gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["GOOD.EXAMPLE.COM"]);
        let mut interner_upper = ChainInterner::new();
        let cred_upper = Credentials::load(&[&leaf_upper], &key_upper, &mut interner_upper)
            .expect("an uppercase SAN still loads");
        let sans_upper: Vec<&str> = cred_upper
            .san_dns_names()
            .iter()
            .map(AsRef::as_ref)
            .collect();
        assert_eq!(sans_upper, vec!["good.example.com"]);
    }

    #[test]
    fn with_staple_refuses_oversize() {
        ensure_provider_installed();
        let (leaf, key) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, &["example.com"]);
        let mut interner = ChainInterner::new();
        let cred = Credentials::load(&[&leaf], &key, &mut interner).expect("valid leaf and key");

        let oversize: Arc<[u8]> = Arc::from(vec![0u8; MAX_STAPLE_BYTES + 1].as_slice());
        let stapled_oversize = cred.with_staple(Some(oversize));
        assert_eq!(stapled_oversize.staple(), None);

        let exact: Arc<[u8]> = Arc::from(vec![7u8; MAX_STAPLE_BYTES].as_slice());
        let stapled_exact = cred.with_staple(Some(exact));
        assert_eq!(
            stapled_exact.staple().map(<[u8]>::len),
            Some(MAX_STAPLE_BYTES)
        );
    }
}
