// SPDX-License-Identifier: MIT OR Apache-2.0

//! Certificate revocation list parsing and compiled revocation indices.
//!
//! `CrlParser` walks a CRL once, extracting only the issuer DN, validity window
//! and revoked serials without materialising the whole structure. `RevocationIndex`
//! answers "is this serial revoked" with one cache-line Bloom probe followed by a
//! binary search over a contiguous sorted array.
//!
//! The expensive path - building an index from millions of serials - is gated on
//! `VerifiedCrl`, which can only be produced by `verify_signature`. That makes
//! "verify before you spend O(r) memory" a compile-time property.

#![allow(
    clippy::integer_division,
    clippy::struct_field_names,
    reason = "integer division: BLOOM_BLOCK_BYTES and 64 are compile-time constants; struct_field_names: issuer_dn and serials are named by the RFC and the issue"
)]

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use siphasher::sip128::{Hasher128, SipHasher13};

use crate::time::UnixSeconds;

// `der::Reader` is the trait that gives `SliceReader` its methods (sequence, tlv_bytes, decode).
use der::Decode;
use der::Reader as _;

/// `deltaCRLIndicator`, RFC 5280 section 5.2.4.
const OID_DELTA_CRL_INDICATOR: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27");

/// SipHash-1-3 key for the Bloom prefilter.
///
/// A fixed key is correct here: the set members are CA-supplied serials, the probe
/// value is the serial a peer presented, and a Bloom false positive costs one binary
/// search rather than an unbounded scan.
const CRL_BLOOM_KEY: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21,
];

/// Bloom filter floor, in bytes.
const BLOOM_FLOOR_BYTES: usize = 2_048;
/// Bloom filter cap, in bytes.
const BLOOM_CAP_BYTES: usize = 4_194_304;
/// Bloom filter bits per entry.
const BLOOM_BITS_PER_ENTRY: usize = 10;
/// Bloom filter block size, in bytes.
const BLOOM_BLOCK_BYTES: usize = 64;
/// Bloom filter probe count.
const BLOOM_K: u64 = 7;

/// CRL handling configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CrlConfig {
    /// Refuse a CRL larger than this. Default `268_435_456` (256 MiB).
    #[serde(default = "d_max_bytes")]
    pub max_bytes: usize,
    /// Refuse a CRL with more entries than this. Default `8_000_000`.
    #[serde(default = "d_max_entries")]
    pub max_entries: usize,
    /// Keep using a CRL this long past `nextUpdate`, with a warning. Default `86_400`.
    #[serde(default = "d_stale_grace")]
    pub stale_grace_secs: u32,
    /// Validity assumed for a CRL with no `nextUpdate`. Default `86_400`.
    #[serde(default = "d_no_next")]
    pub no_next_update_ttl_secs: u32,
    /// Clock skew tolerance on both timestamps. Default 300.
    #[serde(default = "d_skew")]
    pub skew_secs: u32,
}

const fn d_max_bytes() -> usize {
    268_435_456
}

const fn d_max_entries() -> usize {
    8_000_000
}

const fn d_stale_grace() -> u32 {
    86_400
}

const fn d_no_next() -> u32 {
    86_400
}

const fn d_skew() -> u32 {
    300
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            max_bytes: d_max_bytes(),
            max_entries: d_max_entries(),
            stale_grace_secs: d_stale_grace(),
            no_next_update_ttl_secs: d_no_next(),
            skew_secs: d_skew(),
        }
    }
}

/// Why a CRL was rejected.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CrlError {
    /// Zero bytes.
    Empty,
    /// Larger than `max_bytes`.
    TooLarge,
    /// The DER did not decode.
    Parse,
    /// A version field other than v1 or v2.
    UnsupportedVersion,
    /// More entries than `max_entries`.
    TooManyEntries,
    /// A serial longer than 20 octets.
    SerialTooLong,
    /// A delta CRL.
    DeltaCrlUnsupported,
    /// The supplied issuer certificate's subject does not equal the CRL's issuer.
    IssuerMismatch,
    /// The signature algorithm is not one the provider verifies.
    UnsupportedSignatureAlgorithm,
    /// The signature did not verify.
    BadSignature,
    /// `nextUpdate` is already in the past at install time.
    AlreadyExpired,
    /// `thisUpdate` is in the future beyond the skew tolerance.
    NotYetValid,
    /// `install_process_provider` has not run, so no signature can be verified.
    ProviderNotInstalled,
}

impl core::fmt::Display for CrlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CrlError::Empty => "crl is empty",
            CrlError::TooLarge => "crl exceeds the configured maximum size",
            CrlError::Parse => "crl did not decode as DER",
            CrlError::UnsupportedVersion => "crl version is not supported",
            CrlError::TooManyEntries => "crl has more entries than the configured maximum",
            CrlError::SerialTooLong => "crl contains a serial number longer than 20 octets",
            CrlError::DeltaCrlUnsupported => "delta CRLs are not supported",
            CrlError::IssuerMismatch => "crl issuer does not match the issuing certificate",
            CrlError::UnsupportedSignatureAlgorithm => {
                "crl signature algorithm is not supported by the installed provider"
            }
            CrlError::BadSignature => "crl signature did not verify",
            CrlError::AlreadyExpired => "crl nextUpdate is already in the past",
            CrlError::NotYetValid => "crl thisUpdate is in the future",
            CrlError::ProviderNotInstalled => "no crypto provider is installed",
        })
    }
}

impl std::error::Error for CrlError {}

/// What a verifier should do with this index right now.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Freshness {
    /// Inside `nextUpdate`.
    Fresh,
    /// Past `nextUpdate` but within `staleGrace`. Usable, warn.
    Stale,
    /// Past `nextUpdate + staleGrace`. The issuer must fail closed.
    Expired,
}

/// Counters for the revocation path.
#[derive(Debug, Default)]
pub struct RevocationStats {
    /// `tls_crl_lookup_total`
    pub lookups: AtomicU64,
    /// `tls_crl_bloom_reject_total`: answered "not revoked" from the prefilter alone.
    pub bloom_rejects: AtomicU64,
    /// `tls_crl_revoked_total`
    pub revoked: AtomicU64,
    /// `tls_crl_wide_serial_total`
    pub wide_lookups: AtomicU64,
}

/// A borrowed, parsed CRL header plus a serial iterator.
#[derive(Debug, PartialEq)]
pub struct ParsedCrl<'a> {
    issuer_dn: &'a [u8],
    this_update: UnixSeconds,
    next_update: Option<UnixSeconds>,
    tbs_span: &'a [u8],
    /// `TBSCertList`'s own `signature AlgorithmIdentifier` (RFC 5280 5.1.1.2): inside
    /// `tbs_span`, therefore covered by the signature. `verify_signature` selects the
    /// verification algorithm from THIS field, not `outer_sig_alg_der`.
    inner_sig_alg_der: &'a [u8],
    /// The outer `CertificateList.signatureAlgorithm`: outside `tbs_span`, therefore NOT
    /// covered by the signature. RFC 5280 5.1.1.2 requires it be identical to
    /// `inner_sig_alg_der`; `verify_signature` checks that before it selects an algorithm from
    /// either field, so this one is never used to pick the verification algorithm itself
    /// (issue #729, should fix item 4).
    outer_sig_alg_der: &'a [u8],
    signature: &'a [u8],
    serials: &'a [u8],
}

impl<'a> ParsedCrl<'a> {
    /// The issuer subject DN as encoded DER.
    #[must_use]
    pub fn issuer_dn(&self) -> &'a [u8] {
        self.issuer_dn
    }

    /// `thisUpdate`.
    #[must_use]
    pub fn this_update(&self) -> UnixSeconds {
        self.this_update
    }

    /// `nextUpdate`, if present.
    #[must_use]
    pub fn next_update(&self) -> Option<UnixSeconds> {
        self.next_update
    }

    /// Iterate normalized serial content octets. Each item borrows the input.
    pub fn serials(&self) -> impl Iterator<Item = Result<&'a [u8], CrlError>> + '_ {
        SerialIter::new(self.serials)
    }

    /// The encoded `TBSCertList` span, which is the signed message. Used by
    /// `prop_parse_never_panics`'s anti-splicing property to restrict a fuzzed byte flip to
    /// the signed region rather than an unauthenticated trailing one.
    #[cfg(test)]
    pub(crate) fn tbs_span(&self) -> &'a [u8] {
        self.tbs_span
    }
}

/// Iterator over normalized serial content octets. Never allocates.
struct SerialIter<'a> {
    bytes: &'a [u8],
}

impl<'a> SerialIter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> Iterator for SerialIter<'a> {
    type Item = Result<&'a [u8], CrlError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        // Every early return below MUST clear `self.bytes` first. `SerialIter` is not a
        // std `Fuse`: once `next` has returned `Some(Err(_))` for a malformed entry, there
        // is no well-defined "resume point" in `self.bytes` to continue from, so the only
        // safe move is to make the iterator empty and therefore terminate on the very next
        // call. Without this, a caller that drains the iterator with `.count()`, `.collect()`
        // or a `for` loop over attacker-controlled bytes that decode as an endless run of
        // invalid entry TLVs never returns; see the issue this fixes for the 50,000,001-item
        // probe that only stopped because it had its own hard break.
        let Ok(mut reader) = der::SliceReader::new(self.bytes) else {
            self.bytes = &[];
            return Some(Err(CrlError::Parse));
        };
        let Ok(entry_tlv) = reader.tlv_bytes() else {
            self.bytes = &[];
            return Some(Err(CrlError::Parse));
        };
        let consumed = entry_tlv.len();
        let Some(rest) = self.bytes.get(consumed..) else {
            self.bytes = &[];
            return Some(Err(CrlError::Parse));
        };
        self.bytes = rest;

        let serial = match serial_from_entry(entry_tlv) {
            Ok(s) => s,
            Err(e) => {
                self.bytes = &[];
                return Some(Err(e));
            }
        };
        Some(Ok(serial))
    }
}

/// Extract the normalized serial bytes from one `revokedCertificates` entry TLV.
fn serial_from_entry(entry_tlv: &[u8]) -> Result<&[u8], CrlError> {
    let content = read_sequence_content(entry_tlv)?;
    let mut reader = der::SliceReader::new(content).map_err(|_| CrlError::Parse)?;
    let uint_ref: der::asn1::UintRef = reader.decode().map_err(|_| CrlError::Parse)?;
    Ok(normalize_serial(uint_ref.as_bytes()))
}

/// Strip leading zero octets and treat an all-zero serial as the single byte 0x00.
fn normalize_serial(mut bytes: &[u8]) -> &[u8] {
    while let Some((0x00, rest)) = bytes.split_first() {
        if rest.is_empty() {
            break;
        }
        bytes = rest;
    }
    if bytes.is_empty() {
        bytes = &[0x00];
    }
    bytes
}

fn read_sequence_content(bytes: &[u8]) -> Result<&[u8], CrlError> {
    let mut reader = der::SliceReader::new(bytes).map_err(|_| CrlError::Parse)?;
    let header = der::Header::decode(&mut reader).map_err(|_| CrlError::Parse)?;
    header
        .tag
        .assert_eq(der::Tag::Sequence)
        .map_err(|_| CrlError::Parse)?;
    reader
        .read_slice(header.length)
        .map_err(|_| CrlError::Parse)
}

/// Parse a CRL.
///
/// # Errors
/// Any `CrlError` other than the signature and freshness variants, which `verify_signature`
/// and `RevocationIndex::build` return.
pub fn parse<'a>(der: &'a [u8], cfg: &CrlConfig) -> Result<ParsedCrl<'a>, CrlError> {
    if der.is_empty() {
        return Err(CrlError::Empty);
    }
    if der.len() > cfg.max_bytes {
        return Err(CrlError::TooLarge);
    }

    let mut reader = der::SliceReader::new(der).map_err(|_| CrlError::Parse)?;
    let outer_content = read_sequence_content_from_reader(&mut reader)?;
    let mut outer = der::SliceReader::new(outer_content).map_err(|_| CrlError::Parse)?;

    let tbs_tlv = read_next_tlv(&mut outer)?;
    let tbs_span = tbs_tlv;
    let parsed_tbs = parse_tbs_cert_list(tbs_tlv)?;

    let outer_sig_alg_tlv = read_next_tlv(&mut outer)?;
    let sig_value_tlv = read_next_tlv(&mut outer)?;
    let signature = signature_bytes(sig_value_tlv)?;

    Ok(ParsedCrl {
        issuer_dn: parsed_tbs.issuer_dn,
        this_update: parsed_tbs.this_update,
        next_update: parsed_tbs.next_update,
        tbs_span,
        inner_sig_alg_der: parsed_tbs.inner_sig_alg,
        outer_sig_alg_der: outer_sig_alg_tlv,
        signature,
        serials: parsed_tbs.serials,
    })
}

fn read_sequence_content_from_reader<'a>(
    reader: &mut der::SliceReader<'a>,
) -> Result<&'a [u8], CrlError> {
    let header = der::Header::decode(reader).map_err(|_| CrlError::Parse)?;
    header
        .tag
        .assert_eq(der::Tag::Sequence)
        .map_err(|_| CrlError::Parse)?;
    reader
        .read_slice(header.length)
        .map_err(|_| CrlError::Parse)
}

fn read_next_tlv<'a>(reader: &mut der::SliceReader<'a>) -> Result<&'a [u8], CrlError> {
    reader.tlv_bytes().map_err(|_| CrlError::Parse)
}

struct ParsedTbs<'a> {
    issuer_dn: &'a [u8],
    this_update: UnixSeconds,
    next_update: Option<UnixSeconds>,
    /// `TBSCertList`'s own `signature AlgorithmIdentifier` TLV: inside the signed span, unlike
    /// the outer `CertificateList.signatureAlgorithm` (RFC 5280 5.1.1.2).
    inner_sig_alg: &'a [u8],
    serials: &'a [u8],
}

fn parse_tbs_cert_list(tbs_tlv: &[u8]) -> Result<ParsedTbs<'_>, CrlError> {
    let content = read_sequence_content(tbs_tlv)?;
    let mut tbs = der::SliceReader::new(content).map_err(|_| CrlError::Parse)?;

    // Optional version.
    let header = tbs.peek_header().map_err(|_| CrlError::Parse)?;
    if header.tag == der::Tag::Integer {
        let version: der::asn1::UintRef = tbs.decode().map_err(|_| CrlError::Parse)?;
        let bytes = version.as_bytes();
        // DER INTEGER 1, meaning v2.
        if bytes != [0x01] {
            return Err(CrlError::UnsupportedVersion);
        }
    }

    // signature AlgorithmIdentifier: TBSCertList's own copy, inside the signed span. Captured
    // (not discarded) so verify_signature can compare it against the outer
    // signatureAlgorithm and select the verification algorithm from this one (RFC 5280
    // 5.1.1.2; #729 SHOULD_FIX 4).
    let inner_sig_alg = read_next_tlv(&mut tbs)?;

    // issuer Name.
    let issuer_tlv = read_next_tlv(&mut tbs)?;
    let issuer_dn = issuer_tlv;

    // thisUpdate.
    let this_update = read_time(&mut tbs)?;

    // nextUpdate.
    let next_update = read_optional_time(&mut tbs)?;

    // revokedCertificates.
    let serials = read_revoked_certificates(&mut tbs)?;

    // crlExtensions [0] EXPLICIT.
    if tbs.peek_byte().is_some() {
        check_crl_extensions(&mut tbs)?;
    }

    Ok(ParsedTbs {
        issuer_dn,
        this_update,
        next_update,
        inner_sig_alg,
        serials,
    })
}

fn read_time(reader: &mut der::SliceReader<'_>) -> Result<UnixSeconds, CrlError> {
    let header = reader.peek_header().map_err(|_| CrlError::Parse)?;
    match header.tag {
        der::Tag::UtcTime => {
            let t: der::asn1::UtcTime = reader.decode().map_err(|_| CrlError::Parse)?;
            Ok(UnixSeconds::new(t.to_unix_duration().as_secs()))
        }
        der::Tag::GeneralizedTime => {
            let t: der::asn1::GeneralizedTime = reader.decode().map_err(|_| CrlError::Parse)?;
            Ok(UnixSeconds::new(t.to_unix_duration().as_secs()))
        }
        _ => Err(CrlError::Parse),
    }
}

fn read_optional_time(reader: &mut der::SliceReader<'_>) -> Result<Option<UnixSeconds>, CrlError> {
    let Ok(header) = reader.peek_header() else {
        return Ok(None);
    };
    if header.tag == der::Tag::UtcTime || header.tag == der::Tag::GeneralizedTime {
        Ok(Some(read_time(reader)?))
    } else {
        Ok(None)
    }
}

fn read_revoked_certificates<'a>(reader: &mut der::SliceReader<'a>) -> Result<&'a [u8], CrlError> {
    let Ok(header) = reader.peek_header() else {
        return Ok(&[]);
    };
    if header.tag != der::Tag::Sequence {
        return Ok(&[]);
    }

    let revoked_tlv = read_next_tlv(reader)?;
    read_sequence_content(revoked_tlv)
}

fn check_crl_extensions(reader: &mut der::SliceReader<'_>) -> Result<(), CrlError> {
    let header = reader.peek_header().map_err(|_| CrlError::Parse)?;
    if !header.tag.is_context_specific() {
        return Ok(());
    }

    let ext_tlv = read_next_tlv(reader)?;
    let mut ext_reader = der::SliceReader::new(ext_tlv).map_err(|_| CrlError::Parse)?;
    let _header = der::Header::decode(&mut ext_reader).map_err(|_| CrlError::Parse)?;
    let inner_seq_tlv = read_next_tlv(&mut ext_reader)?;
    let inner_content = read_sequence_content(inner_seq_tlv)?;

    let mut inner = der::SliceReader::new(inner_content).map_err(|_| CrlError::Parse)?;
    while inner.peek_byte().is_some() {
        let ext_tlv = read_next_tlv(&mut inner)?;
        let oid = extension_oid(ext_tlv)?;
        if oid == OID_DELTA_CRL_INDICATOR {
            return Err(CrlError::DeltaCrlUnsupported);
        }
    }

    Ok(())
}

fn extension_oid(ext_tlv: &[u8]) -> Result<der::asn1::ObjectIdentifier, CrlError> {
    let content = read_sequence_content(ext_tlv)?;
    let mut reader = der::SliceReader::new(content).map_err(|_| CrlError::Parse)?;
    let oid: der::asn1::ObjectIdentifier = reader.decode().map_err(|_| CrlError::Parse)?;
    Ok(oid)
}

fn signature_bytes(sig_value_tlv: &[u8]) -> Result<&[u8], CrlError> {
    let mut reader = der::SliceReader::new(sig_value_tlv).map_err(|_| CrlError::Parse)?;
    let bit_string: der::asn1::BitStringRef = reader.decode().map_err(|_| CrlError::Parse)?;
    Ok(bit_string.raw_bytes())
}

/// A CRL whose signature has been verified against its issuing certificate.
#[derive(Debug, PartialEq)]
pub struct VerifiedCrl<'a> {
    parsed: ParsedCrl<'a>,
}

impl<'a> VerifiedCrl<'a> {
    /// The issuer subject DN as encoded DER.
    #[must_use]
    pub fn issuer_dn(&self) -> &'a [u8] {
        self.parsed.issuer_dn
    }

    /// `thisUpdate`.
    #[must_use]
    pub fn this_update(&self) -> UnixSeconds {
        self.parsed.this_update
    }

    /// `nextUpdate`, if present.
    #[must_use]
    pub fn next_update(&self) -> Option<UnixSeconds> {
        self.parsed.next_update
    }
}

/// Verify a parsed CRL against its issuing certificate, consuming it.
///
/// # Errors
/// `CrlError::IssuerMismatch`, `CrlError::UnsupportedSignatureAlgorithm`, `CrlError::BadSignature`.
pub fn verify_signature<'a>(
    parsed: ParsedCrl<'a>,
    issuer_der: &[u8],
) -> Result<VerifiedCrl<'a>, CrlError> {
    let issuer = x509_cert::Certificate::from_der(issuer_der).map_err(|_| CrlError::Parse)?;
    let issuer_subject = x509_cert::der::Encode::to_der(&issuer.tbs_certificate.subject)
        .map_err(|_| CrlError::Parse)?;
    if issuer_subject.as_slice() != parsed.issuer_dn {
        return Err(CrlError::IssuerMismatch);
    }

    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let spki_alg_der =
        x509_cert::der::Encode::to_der(&spki.algorithm).map_err(|_| CrlError::Parse)?;
    let public_key_bytes = spki.subject_public_key.raw_bytes();

    // `rustls_pki_types::AlgorithmIdentifier` holds the SEQUENCE CONTENTS of an
    // AlgorithmIdentifier, not the full TLV: see its own doc example, which builds
    // `RSA_ENCRYPTION` from bytes starting at 0x06 (OBJECT IDENTIFIER) with no leading
    // `0x30 <len>` SEQUENCE header. `parsed.inner_sig_alg_der` and `spki_alg_der` are both full
    // TLVs (one captured via `der::Reader::tlv_bytes`, the other emitted by `Encode::to_der`),
    // so comparing them directly against the constants can never match. Strip the outer
    // SEQUENCE header from each with a real DER parser before comparing contents to contents;
    // a SEQUENCE header is not a fixed-width prefix, so this cannot be a hardcoded byte
    // offset. The parameters field (for example RSA's `NULL {}`) stays part of the compared
    // content on both sides, since it is part of the algorithm's identity.
    let inner_sig_alg_content = read_sequence_content(parsed.inner_sig_alg_der)?;
    let spki_alg_content = read_sequence_content(spki_alg_der.as_slice())?;

    // RFC 5280 5.1.1.2: TBSCertList's own `signature` field and the outer
    // `signatureAlgorithm` MUST be identical. The outer field sits OUTSIDE `tbs_span`, so it
    // is not covered by the signature; selecting the verification algorithm from it (as
    // opposed to the inner, signed copy) would let an off-path attacker who controls only the
    // outer bytes steer which algorithm this function trusts, without ever having the issuing
    // key. Compare before selecting, and select from the inner field, never the outer one
    // (#729 SHOULD_FIX 4).
    let outer_sig_alg_content = read_sequence_content(parsed.outer_sig_alg_der)?;
    if inner_sig_alg_content != outer_sig_alg_content {
        return Err(CrlError::UnsupportedSignatureAlgorithm);
    }

    let provider = crate::provider::provider().ok_or(CrlError::ProviderNotInstalled)?;
    let alg = provider
        .signature_verification_algorithms
        .all
        .iter()
        .find(|a| {
            a.signature_alg_id().as_ref() == inner_sig_alg_content
                && a.public_key_alg_id().as_ref() == spki_alg_content
        })
        .ok_or(CrlError::UnsupportedSignatureAlgorithm)?;

    alg.verify_signature(public_key_bytes, parsed.tbs_span, parsed.signature)
        .map_err(|_| CrlError::BadSignature)?;

    Ok(VerifiedCrl { parsed })
}

/// Compiled revocation data for one issuer. Immutable.
#[derive(Debug)]
pub struct RevocationIndex {
    issuer_dn: Box<[u8]>,
    bloom: Box<[u64]>,
    blocks: u32,
    serials: Box<[u128]>,
    wide: HashSet<Box<[u8]>>,
    this_update: UnixSeconds,
    next_update: Option<UnixSeconds>,
    stats: RevocationStats,
}

// PartialEq is manual because AtomicU64 in RevocationStats does not implement it.
// The stats counters are compared by identity (they should be zero for a fresh index).
impl PartialEq for RevocationIndex {
    fn eq(&self, other: &Self) -> bool {
        self.issuer_dn == other.issuer_dn
            && self.bloom == other.bloom
            && self.blocks == other.blocks
            && self.serials == other.serials
            && self.wide == other.wide
            && self.this_update == other.this_update
            && self.next_update == other.next_update
    }
}

impl RevocationIndex {
    /// Build an index from a signature-verified CRL.
    ///
    /// Taking `&VerifiedCrl` rather than `&ParsedCrl` is deliberate: building an index is the
    /// expensive step (O(r) collection, an O(r log r) sort, and up to 128 MB of serials at
    /// `max_entries`), and it must never run for a CRL an attacker supplied and we have not
    /// authenticated.
    ///
    /// # Errors
    /// `CrlError::Parse`, `CrlError::TooManyEntries`, `CrlError::SerialTooLong`,
    /// `CrlError::AlreadyExpired`, `CrlError::NotYetValid`. `Parse` propagates from the
    /// `Result` the serial iterator yields (see `SerialIter::next`) via the `?` on `item`
    /// below; `parse` itself is infallible once it has already returned a `ParsedCrl`.
    pub fn build(
        verified: &VerifiedCrl<'_>,
        now: UnixSeconds,
        cfg: &CrlConfig,
    ) -> Result<Self, CrlError> {
        let skew = u64::from(cfg.skew_secs);
        if verified.this_update().get() > now.get().saturating_add(skew) {
            // thisUpdate is in the future beyond skew.
            return Err(CrlError::NotYetValid);
        }

        if let Some(next) = verified.next_update() {
            if next.get().saturating_add(skew) < now.get() {
                return Err(CrlError::AlreadyExpired);
            }
        } else {
            // No nextUpdate: apply the same refusal using freshness's own synthetic expiry
            // (thisUpdate + no_next_update_ttl_secs), so a CRL cannot be installed already past
            // its own synthetic expiry window. Without this, build returned Ok for a CRL whose
            // freshness() already reported Expired at the instant of construction: a CRL 22
            // years past its synthetic expiry built successfully (#729 SHOULD_FIX 5).
            let synthetic_next = verified
                .this_update()
                .saturating_add_secs(u64::from(cfg.no_next_update_ttl_secs));
            if synthetic_next.get().saturating_add(skew) < now.get() {
                return Err(CrlError::AlreadyExpired);
            }
        }

        let mut serials_vec: Vec<u128> = Vec::new();
        let mut wide_set: HashSet<Box<[u8]>> = HashSet::new();

        for item in verified.parsed.serials() {
            let serial = item?;
            if serials_vec.len().saturating_add(wide_set.len()) >= cfg.max_entries {
                return Err(CrlError::TooManyEntries);
            }
            if serial.len() > 20 {
                return Err(CrlError::SerialTooLong);
            }
            if serial.len() > 16 {
                #[cfg(test)]
                crate::name::alloc_probe::record(serial.len());
                wide_set.insert(serial.to_vec().into_boxed_slice());
            } else {
                #[cfg(test)]
                let cap_before = serials_vec.capacity();
                serials_vec.push(pack_serial(serial));
                #[cfg(test)]
                {
                    let cap_after = serials_vec.capacity();
                    if cap_after > cap_before {
                        // Vec's growth strategy performs exactly one reallocation per capacity
                        // increase; the delta in capacity is the delta in bytes actually
                        // allocated for this element type, independent of how many elements
                        // are logically present yet. This is what lets
                        // crl_parse_1e6_allocation_bounded see the transient over-allocation
                        // from push()'s doubling growth, not just the final structure's size.
                        crate::name::alloc_probe::record(
                            (cap_after - cap_before) * core::mem::size_of::<u128>(),
                        );
                    }
                }
            }
        }

        serials_vec.sort_unstable();
        serials_vec.dedup();

        #[cfg(test)]
        if serials_vec.capacity() != serials_vec.len() {
            // into_boxed_slice() below reallocates to the exact length when capacity and
            // length differ (the common case after dedup shrinks the logical length below the
            // capacity push() grew).
            crate::name::alloc_probe::record(serials_vec.len() * core::mem::size_of::<u128>());
        }

        let bloom = build_bloom(&serials_vec, &wide_set);
        let blocks = u32::try_from(bloom.len() / (BLOOM_BLOCK_BYTES / 8))
            .map_err(|_| CrlError::TooManyEntries)?;

        #[cfg(test)]
        crate::name::alloc_probe::record(verified.parsed.issuer_dn.len());

        Ok(Self {
            issuer_dn: verified.parsed.issuer_dn.to_vec().into_boxed_slice(),
            bloom,
            blocks,
            serials: serials_vec.into_boxed_slice(),
            wide: wide_set,
            this_update: verified.parsed.this_update,
            next_update: verified.parsed.next_update,
            stats: RevocationStats::default(),
        })
    }

    /// Whether `serial` is revoked. Allocation-free.
    #[must_use]
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        let normalized = normalize_serial(serial);
        if normalized.len() > 16 {
            self.stats.wide_lookups.fetch_add(1, Ordering::Relaxed);
            let found = self.wide.contains(normalized);
            if found {
                self.stats.revoked.fetch_add(1, Ordering::Relaxed);
            }
            return found;
        }

        let packed = pack_serial(normalized);
        if !self.bloom_probe(packed) {
            self.stats.bloom_rejects.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let found = self.serials.binary_search(&packed).is_ok();
        if found {
            self.stats.revoked.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    fn bloom_probe(&self, packed: u128) -> bool {
        let (h1, h2) = bloom_hashes(packed);
        let blocks = u64::from(self.blocks);
        let block = h1 % blocks;
        let base = usize::try_from(block * (BLOOM_BLOCK_BYTES as u64 / 8)).unwrap_or(0);
        let mut present = true;
        for i in 0..BLOOM_K {
            let bit = ((h1.wrapping_add(i.wrapping_mul(h2))) & 0x1ff) as usize; // 0..511
            let word = base + (bit / 64);
            let bit_mask = 1u64 << (bit % 64);
            if let Some(v) = self.bloom.get(word) {
                present &= (*v & bit_mask) != 0;
            } else {
                present = false;
            }
        }
        present
    }

    /// Freshness at `now`.
    #[must_use]
    pub fn freshness(&self, now: UnixSeconds, cfg: &CrlConfig) -> Freshness {
        let effective_next = match self.next_update {
            Some(n) => n,
            None => self
                .this_update
                .saturating_add_secs(u64::from(cfg.no_next_update_ttl_secs)),
        };
        if now <= effective_next {
            return Freshness::Fresh;
        }
        let grace_end = effective_next.saturating_add_secs(u64::from(cfg.stale_grace_secs));
        if now <= grace_end {
            Freshness::Stale
        } else {
            Freshness::Expired
        }
    }

    /// Number of distinct revoked serials.
    #[must_use]
    pub fn len(&self) -> usize {
        self.serials.len() + self.wide.len()
    }

    /// Whether the CRL revokes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.serials.is_empty() && self.wide.is_empty()
    }

    /// Total bytes held. Exported as `tls_crl_index_bytes`.
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        self.issuer_dn.len()
            + self.bloom.len() * 8
            + self.serials.len() * 16
            + self.wide.iter().map(|s| s.len() + 8).sum::<usize>()
    }

    /// The issuer this index covers.
    #[must_use]
    pub fn issuer_dn(&self) -> &[u8] {
        &self.issuer_dn
    }
}

fn pack_serial(serial: &[u8]) -> u128 {
    let mut out = [0u8; 16];
    let start = 16usize.saturating_sub(serial.len());
    #[allow(
        clippy::collapsible_if,
        reason = "the let take = statement between the outer if-let and the inner pair prevents collapsing without introducing a closure or duplicating the min() call"
    )]
    if let Some(slice) = out.get_mut(start..) {
        let take = slice.len().min(serial.len());
        if let Some(target) = slice.get_mut(..take)
            && let Some(source) = serial.get(serial.len().saturating_sub(take)..)
        {
            target.copy_from_slice(source);
        }
    }
    u128::from_be_bytes(out)
}

fn bloom_hashes(packed: u128) -> (u64, u64) {
    let mut hasher = SipHasher13::new_with_key(&CRL_BLOOM_KEY);
    core::hash::Hasher::write(&mut hasher, &packed.to_be_bytes());
    let h128 = hasher.finish128();
    (h128.h1, h128.h2)
}

fn build_bloom(serials: &[u128], wide: &HashSet<Box<[u8]>>) -> Box<[u64]> {
    let entries = serials.len().saturating_add(wide.len());
    let bits = entries
        .saturating_mul(BLOOM_BITS_PER_ENTRY)
        .clamp(BLOOM_FLOOR_BYTES * 8, BLOOM_CAP_BYTES * 8);
    // Round bits up to a multiple of 512 (one block).
    let bits = bits.div_ceil(512) * 512;
    let words = bits / 64;
    let mut bloom = vec![0u64; words];
    #[cfg(test)]
    crate::name::alloc_probe::record(words * core::mem::size_of::<u64>());
    let blocks = u64::try_from(words / (BLOOM_BLOCK_BYTES / 8)).unwrap_or(1);

    for packed in serials {
        bloom_insert(&mut bloom, blocks, *packed);
    }
    for serial in wide {
        let mut buf = [0u8; 16];
        let len = serial.len().min(16);
        if let Some(src) = serial.get(..len)
            && let Some(dst) = buf.get_mut(16 - len..)
        {
            dst.copy_from_slice(src);
        }
        bloom_insert(&mut bloom, blocks, u128::from_be_bytes(buf));
    }

    bloom.into_boxed_slice()
}

fn bloom_insert(bloom: &mut [u64], blocks: u64, packed: u128) {
    let (h1, h2) = bloom_hashes(packed);
    let block = h1 % blocks;
    let base = usize::try_from(block * (BLOOM_BLOCK_BYTES as u64 / 8)).unwrap_or(0);
    for i in 0..BLOOM_K {
        let bit = ((h1.wrapping_add(i.wrapping_mul(h2))) & 0x1ff) as usize;
        let word = base + (bit / 64);
        if let Some(v) = bloom.get_mut(word) {
            *v |= 1u64 << (bit % 64);
        }
    }
}

/// Every issuer's index, published as one immutable value.
pub struct CrlSet {
    by_issuer: std::collections::HashMap<[u8; 16], Arc<RevocationIndex>>,
    generation: u64,
}

impl CrlSet {
    /// An empty set.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            by_issuer: std::collections::HashMap::new(),
            generation: 0,
        }
    }

    /// Build from indices, keyed by `blake3(issuer_dn)[..16]`.
    ///
    /// When two indices carry the same issuer DN, the one with the later `this_update` is kept and
    /// the other is discarded; ties keep the first in iteration order. Discards are not an error.
    #[must_use]
    pub fn from_indices(indices: Vec<Arc<RevocationIndex>>, generation: u64) -> Self {
        let mut by_issuer = std::collections::HashMap::with_capacity(indices.len());
        for idx in indices {
            let mut hash = [0u8; 16];
            let full = blake3::hash(idx.issuer_dn());
            if let Some(src) = full.as_bytes().get(..16) {
                hash.copy_from_slice(src);
            }
            by_issuer
                .entry(hash)
                .and_modify(|existing: &mut Arc<RevocationIndex>| {
                    if idx.this_update > existing.this_update {
                        *existing = idx.clone();
                    }
                })
                .or_insert(idx);
        }
        Self {
            by_issuer,
            generation,
        }
    }

    /// The index for a certificate's issuer, if we hold one.
    ///
    /// Hashes `issuer_dn` with BLAKE3, probes `by_issuer`, and then compares the candidate's stored
    /// `issuer_dn()` byte for byte before returning it, so a hash collision can never attach one
    /// issuer's revocation list to another's certificates.
    #[must_use]
    pub fn for_issuer(&self, issuer_dn: &[u8]) -> Option<&Arc<RevocationIndex>> {
        let mut hash = [0u8; 16];
        let full = blake3::hash(issuer_dn);
        if let Some(src) = full.as_bytes().get(..16) {
            hash.copy_from_slice(src);
        }
        let candidate = self.by_issuer.get(&hash)?;
        if candidate.issuer_dn() == issuer_dn {
            Some(candidate)
        } else {
            None
        }
    }

    /// Number of issuers covered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_issuer.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_issuer.is_empty()
    }

    /// Generation number.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::alloc_probe;
    use proptest::prelude::*;

    // -----------------------------------------------------------------------
    // DER builder helpers for test CRL fixtures.
    //
    // We write tag/length/bytes manually to avoid depending on der::Tag::ContextSpecific
    // (which uses a private TagNumber type) and on Length::new with large values.
    // -----------------------------------------------------------------------

    mod der_enc {
        use der::DateTime;
        use der::Encode;
        use der::asn1::{BitStringRef, GeneralizedTime, ObjectIdentifier, UtcTime};

        #[allow(
            clippy::cast_possible_truncation,
            reason = "all casts are guarded by size checks: len < 128, < 256, < 65536, etc; values are known to fit in u8 at each call site"
        )]
        fn der_length(buf: &mut Vec<u8>, len: usize) {
            if len < 128 {
                buf.push(len as u8);
            } else if len < 256 {
                buf.push(0x81);
                buf.push(len as u8);
            } else if len < 65_536 {
                buf.push(0x82);
                buf.push((len >> 8) as u8);
                buf.push((len & 0xff) as u8);
            } else if len < 16_777_216 {
                buf.push(0x83);
                buf.push((len >> 16) as u8);
                buf.push((len >> 8) as u8);
                buf.push((len & 0xff) as u8);
            } else {
                buf.push(0x84);
                buf.push((len >> 24) as u8);
                buf.push((len >> 16) as u8);
                buf.push((len >> 8) as u8);
                buf.push((len & 0xff) as u8);
            }
        }

        fn encode_tag_raw(tag_byte: u8, content: &[u8]) -> Vec<u8> {
            let mut buf = vec![tag_byte];
            der_length(&mut buf, content.len());
            buf.extend_from_slice(content);
            buf
        }

        pub(crate) fn encode_sequence(items: &[impl AsRef<[u8]>]) -> Vec<u8> {
            let body: Vec<u8> = items
                .iter()
                .flat_map(|i| i.as_ref().iter().copied())
                .collect();
            encode_tag_raw(0x30, &body)
        }

        pub(crate) fn encode_integer(bytes: &[u8]) -> Vec<u8> {
            // DER requires a leading 0x00 when the first content byte has the
            // high bit set, so the INTEGER is interpreted as positive.
            if bytes.first().is_some_and(|b| b & 0x80 != 0) {
                let mut padded = vec![0x00];
                padded.extend_from_slice(bytes);
                encode_tag_raw(0x02, &padded)
            } else {
                encode_tag_raw(0x02, bytes)
            }
        }

        pub(crate) fn encode_set(content: &[u8]) -> Vec<u8> {
            encode_tag_raw(0x31, content)
        }

        pub(crate) fn encode_octet_string(content: &[u8]) -> Vec<u8> {
            encode_tag_raw(0x04, content)
        }

        pub(crate) fn encode_oid(oid_str: &str) -> Vec<u8> {
            let oid: ObjectIdentifier = oid_str.parse().unwrap();
            let mut buf = Vec::new();
            oid.encode(&mut buf).unwrap();
            buf
        }

        pub(crate) fn encode_utctime(secs: u64) -> Vec<u8> {
            let dt = date_time_from_unix(secs);
            let t = UtcTime::from_date_time(dt).unwrap();
            let mut buf = Vec::new();
            t.encode(&mut buf).unwrap();
            buf
        }

        /// Used by `crl_generalized_time_this_update_parses`: #123's design allows
        /// `thisUpdate`/`nextUpdate` to be encoded as either `UTCTime` or `GeneralizedTime`, and
        /// every other fixture in this module only ever encodes `UTCTime`.
        pub(crate) fn encode_generalized_time(secs: u64) -> Vec<u8> {
            let dt = date_time_from_unix(secs);
            let t = GeneralizedTime::from_date_time(dt);
            let mut buf = Vec::new();
            t.encode(&mut buf).unwrap();
            buf
        }

        #[allow(
            clippy::many_single_char_names,
            reason = "h/m/s/d/y are the conventional names for hours/minutes/seconds/days/years in date arithmetic; longer names would be less readable"
        )]
        fn date_time_from_unix(secs: u64) -> DateTime {
            // Compute a DateTime from seconds since epoch using a simple algorithm.
            // Sufficiently accurate for test UTCTime values.
            let days = secs / 86_400;
            let rem = secs % 86_400;
            let h = (rem / 3600) as u8;
            let m = ((rem % 3600) / 60) as u8;
            let s = (rem % 60) as u8;

            #[allow(
                clippy::cast_possible_wrap,
                reason = "days since epoch fits in i64 for any timestamp this test module produces (well under 2^63)"
            )]
            let mut d = days as i64;
            let mut y = 1970i64;

            loop {
                let days_in_year = if is_leap(y) { 366 } else { 365 };
                if d < days_in_year {
                    break;
                }
                d -= days_in_year;
                y += 1;
            }

            let month_days = if is_leap(y) {
                [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            } else {
                [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            };

            let mut mo = 1u8;
            for &md in &month_days {
                if d < i64::from(md) {
                    break;
                }
                d -= i64::from(md);
                mo += 1;
            }

            DateTime::new(
                u16::try_from(y).unwrap(),
                mo,
                u8::try_from(d + 1).unwrap(),
                h,
                m,
                s,
            )
            .unwrap()
        }

        fn is_leap(y: i64) -> bool {
            (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
        }

        pub(crate) fn encode_bit_string(bytes: &[u8]) -> Vec<u8> {
            let bs = BitStringRef::new(0, bytes).unwrap();
            let mut buf = Vec::new();
            bs.encode(&mut buf).unwrap();
            buf
        }

        pub(crate) fn encode_name(rdn_oid: &str, value: &str) -> Vec<u8> {
            let set = encode_set(&encode_sequence(&[
                encode_oid(rdn_oid),
                encode_tag_raw(0x13, value.as_bytes()), // PrintableString
            ]));
            encode_sequence(&[set])
        }

        pub(crate) fn encode_algorithm_identifier(oid_str: &str) -> Vec<u8> {
            encode_sequence(&[encode_oid(oid_str)])
        }

        pub(crate) fn encode_context_explicit(tag: u8, content: &[u8]) -> Vec<u8> {
            // Context-specific constructed: tag byte = 0xa0 | tag_number
            encode_tag_raw(0xa0 | tag, content)
        }
    }

    /// Build a structurally valid CRL DER blob for testing.
    ///
    /// `serials` are the raw content octets of the serial INTEGERs (before DER encoding).
    /// `this_update` and `next_update` are Unix timestamps; `None` means absent.
    /// `has_delta` adds a `deltaCRLIndicator` extension.
    fn build_crl_der(
        serials: &[&[u8]],
        this_update: Option<u64>,
        next_update: Option<u64>,
        has_delta: bool,
    ) -> Vec<u8> {
        let now = this_update.unwrap_or(1_704_000_000);
        let later = next_update.unwrap_or(now + 86_400);

        let mut tbs_items = vec![
            // Version (v2, INTEGER 1)
            der_enc::encode_integer(&[0x01]),
            // AlgorithmIdentifier (sha256WithRSAEncryption)
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            // Issuer Name
            der_enc::encode_name("2.5.4.3", "Test CA"),
            // thisUpdate
            der_enc::encode_utctime(now),
            // nextUpdate (optional)
            der_enc::encode_utctime(later),
        ];

        // revokedCertificates (optional)
        if !serials.is_empty() {
            let entries: Vec<Vec<u8>> = serials
                .iter()
                .map(|s| {
                    der_enc::encode_sequence(&[
                        der_enc::encode_integer(s),
                        der_enc::encode_utctime(now),
                    ])
                })
                .collect();
            let entry_refs: Vec<&[u8]> = entries.iter().map(std::vec::Vec::as_slice).collect();
            tbs_items.push(der_enc::encode_sequence(&entry_refs));
        }

        // crlExtensions [0] EXPLICIT (optional)
        if has_delta {
            let ext = der_enc::encode_sequence(&[
                der_enc::encode_oid("2.5.29.27"),
                der_enc::encode_octet_string(&[]),
            ]);
            let ext_seq = der_enc::encode_sequence(&[ext]);
            tbs_items.push(der_enc::encode_context_explicit(0, &ext_seq));
        }

        let tbs = der_enc::encode_sequence(&tbs_items);

        let sig_alg = der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11");
        let sig_value = der_enc::encode_bit_string(&[0u8; 256]);

        der_enc::encode_sequence(&[tbs, sig_alg, sig_value])
    }

    // -----------------------------------------------------------------------
    // Real signing fixture for `verify_signature`.
    //
    // `verify_signature` performs a genuine cryptographic check (that is the entire point of
    // #726), so any test that needs a `VerifiedCrl` must obtain one from a CRL that is
    // actually, validly signed against a real issuing certificate. `CaFixture` is a real
    // self-signed RSA-2048 CA, generated once and shared by every test below: RSA-2048 key
    // generation is the expensive part, not the per-call sign, so one process-wide fixture
    // (mirroring the fuzz target's own `Fixture` in fuzz_targets/fuzz_crl_parse.rs) keeps the
    // whole suite fast.
    // -----------------------------------------------------------------------

    /// `verify_signature` needs a process-wide crypto provider installed to find a matching
    /// signature-verification algorithm; without one it fails closed with
    /// `CrlError::ProviderNotInstalled` before it ever reaches the comparison this module
    /// exists to fix. Installation is process-global and idempotent (`Ok` and
    /// `AlreadyInstalled` both leave a provider installed), so one `Once` shared by every test
    /// in this module is enough; mirrors `store::index::tests::ensure_provider_installed` and
    /// `store::cred::tests::ensure_provider_installed`.
    fn ensure_provider_installed() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test module's own ensure_provider_installed() installs the process-wide provider; either outcome (Ok or AlreadyInstalled) leaves a provider installed, which is all this helper promises.
        });
    }

    struct CaFixture {
        key_pair: rcgen::KeyPair,
        issuer_der: Vec<u8>,
        /// The fixture certificate's own subject, DER-encoded exactly the way
        /// `verify_signature` encodes it (`x509_cert::der::Encode::to_der` on the parsed
        /// certificate's `subject`), so a CRL built with this as its issuer field is byte-for-
        /// byte accepted by the issuer check.
        subject_dn: Vec<u8>,
    }

    fn ca_fixture() -> &'static CaFixture {
        static FIXTURE: std::sync::OnceLock<CaFixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose};
            ensure_provider_installed();
            let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
                .expect("RSA-2048 key generation for a fixed algorithm must not fail in a test");
            let mut params = CertificateParams::new(vec!["cafixture.test".to_owned()])
                .expect("a single ASCII SAN must always build valid CertificateParams");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let cert = params
                .self_signed(&key_pair)
                .expect("self-signing a fixed CA template must not fail in a test");
            let issuer_der = cert.der().to_vec();

            let parsed_cert = x509_cert::Certificate::from_der(&issuer_der)
                .expect("rcgen must emit a certificate that x509_cert can parse back");
            let subject_dn = x509_cert::der::Encode::to_der(&parsed_cert.tbs_certificate.subject)
                .expect("a parsed Name must re-encode to DER");

            CaFixture {
                key_pair,
                issuer_der,
                subject_dn,
            }
        })
    }

    /// Encode `tbs_items` as a `TBSCertList` SEQUENCE, sign it with `fx`'s real key, and wrap
    /// the result as a complete `CertificateList` DER blob: a real RSA-PKCS1-SHA256 signature
    /// over the exact bytes `verify_signature` will re-hash, in place of the placeholder
    /// `[0u8; 256]` the unsigned `build_crl_der` above writes.
    fn sign_tbs_into_crl(tbs_items: &[Vec<u8>], fx: &CaFixture) -> Vec<u8> {
        let tbs = der_enc::encode_sequence(tbs_items);
        let sig_alg = der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11");
        let signature = rcgen::SigningKey::sign(&fx.key_pair, &tbs)
            .expect("RSA signing must not fail for a well-formed TBS in a test fixture");
        let sig_value = der_enc::encode_bit_string(&signature);
        der_enc::encode_sequence(&[tbs, sig_alg, sig_value])
    }

    /// Same shape and parameters as `build_crl_der` (fine-grained control over serials and
    /// timestamps for edge cases), but the issuer field is `ca_fixture()`'s own real subject
    /// and the signature is real, so the result is accepted by `verify_signature`, not just
    /// by `parse`.
    fn build_signed_crl_der(
        serials: &[&[u8]],
        this_update: Option<u64>,
        next_update: Option<u64>,
    ) -> Vec<u8> {
        let fx = ca_fixture();
        let now = this_update.unwrap_or(1_704_000_000);
        let later = next_update.unwrap_or(now + 86_400);

        let mut tbs_items = vec![
            der_enc::encode_integer(&[0x01]),
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            fx.subject_dn.clone(),
            der_enc::encode_utctime(now),
            der_enc::encode_utctime(later),
        ];

        if !serials.is_empty() {
            let entries: Vec<Vec<u8>> = serials
                .iter()
                .map(|s| {
                    der_enc::encode_sequence(&[
                        der_enc::encode_integer(s),
                        der_enc::encode_utctime(now),
                    ])
                })
                .collect();
            let entry_refs: Vec<&[u8]> = entries.iter().map(std::vec::Vec::as_slice).collect();
            tbs_items.push(der_enc::encode_sequence(&entry_refs));
        }

        sign_tbs_into_crl(&tbs_items, fx)
    }

    /// Build a validly signed CRL with a single serial.
    fn build_single_signed_crl(serial: &[u8]) -> Vec<u8> {
        build_signed_crl_der(&[serial], None, None)
    }

    fn default_cfg() -> CrlConfig {
        CrlConfig {
            max_bytes: 1_000_000_000,
            max_entries: 10_000_000,
            stale_grace_secs: 86_400,
            no_next_update_ttl_secs: 86_400,
            skew_secs: 300,
        }
    }

    // -----------------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn crl_empty() {
        let cfg = default_cfg();
        assert_eq!(parse(&[], &cfg), Err(CrlError::Empty));
    }

    #[test]
    fn crl_no_revoked_list() {
        let der = build_signed_crl_der(&[], None, None);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("CRL with no revoked list should parse");
        assert_eq!(parsed.serials().count(), 0);
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
        assert!(!idx.is_revoked(&[0x01]));
    }

    #[test]
    fn crl_single_entry() {
        let der = build_single_signed_crl(&[0x2a]); // serial 42
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("CRL with one entry should parse");
        assert_eq!(parsed.serials().count(), 1);
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        assert_eq!(idx.len(), 1);
        assert!(!idx.is_empty());
        assert!(idx.is_revoked(&[0x2a]));
        assert!(!idx.is_revoked(&[0x01]));
    }

    #[test]
    fn crl_max_bytes_boundary() {
        let mut cfg = default_cfg();
        cfg.max_bytes = 100;
        let der = [0u8; 100];
        // Exactly max_bytes should parse (and fail at DER parse, not size)
        let parsed = parse(&der, &cfg);
        assert_eq!(parsed.err(), Some(CrlError::Parse));
        // One over should be TooLarge
        cfg.max_bytes = 99;
        assert_eq!(parse(&[0u8; 100], &cfg), Err(CrlError::TooLarge));
    }

    #[test]
    fn crl_max_entries_boundary() {
        let mut cfg = default_cfg();
        cfg.max_entries = 5;
        cfg.max_bytes = 1_000_000_000;
        let serials: Vec<Vec<u8>> = (0..5).map(|i| vec![i + 1]).collect();
        let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
        let der = build_signed_crl_der(&serial_refs, None, None);
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("5 entries with max_entries=5 should build");
        assert_eq!(idx.len(), 5);

        // One over
        let serials: Vec<Vec<u8>> = (0..6).map(|i| vec![i + 1]).collect();
        let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
        let der = build_signed_crl_der(&serial_refs, None, None);
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        assert_eq!(
            RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg),
            Err(CrlError::TooManyEntries)
        );
    }

    #[test]
    fn crl_serial_21_bytes() {
        // 21-byte serial should be rejected (RFC 5280 limits to 20)
        // Use non-zero content so the DER INTEGER encoding is valid
        // (all-zeros would be invalid DER due to leading zero rule).
        let serial: Vec<u8> = vec![0x01; 21];
        let der = build_single_signed_crl(&serial);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        // The serial in the CRL has 21 content octets.
        // After normalization, it's still 21 bytes (no leading zero to strip).
        assert_eq!(
            RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg),
            Err(CrlError::SerialTooLong)
        );

        // 21 content octets with leading zero -> normalizes to 20 -> accepted
        let serial: Vec<u8> = {
            let mut s = vec![0x00];
            s.extend_from_slice(&[0xaa; 20]);
            s
        };
        let der = build_single_signed_crl(&serial);
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("20-byte normalized serial should build");
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn crl_serial_17_bytes_wide() {
        // A 17-byte serial should go into the wide set.
        // Use bytes with high bit clear so DER INTEGER encoding is valid.
        let serial = [0x0a; 17];
        let der = build_single_signed_crl(&serial);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        assert_eq!(idx.len(), 1);
        assert!(idx.is_revoked(&serial));
        assert!(!idx.is_revoked(&[0xbb; 17]));
    }

    #[test]
    fn crl_serial_leading_zero_16_bytes() {
        // 17 content octets: 00 FF FF ... FF (17 bytes) -> normalizes to 16 bytes -> in serials
        let serial_der = {
            let mut s = vec![0x00];
            s.extend_from_slice(&[0xff; 16]);
            s
        };
        let der = build_single_signed_crl(&serial_der);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        assert_eq!(idx.len(), 1);
        // After normalization, the serial is [0xff; 16]
        assert!(idx.is_revoked(&[0xff; 16]));
        // Same serial with DER padding (00 FF...FF)
        let mut with_padding = vec![0x00];
        with_padding.extend_from_slice(&[0xff; 16]);
        assert!(idx.is_revoked(&with_padding));
        // Should have 0 wide serials
        assert!(idx.wide().is_empty());
    }

    #[test]
    fn crl_serial_zero() {
        let der = build_single_signed_crl(&[0x00]);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        assert_eq!(idx.len(), 1);
        // Serial 0 normalizes to [0x00]
        assert!(idx.is_revoked(&[0x00]));
        // Also matches when given with leading zeros
        assert!(idx.is_revoked(&[0x00, 0x00]));
    }

    #[test]
    fn crl_duplicate_serials() {
        let der = build_signed_crl_der(&[&[0x01], &[0x01], &[0x02]], None, None);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        assert_eq!(idx.len(), 2); // deduplicated
    }

    #[test]
    fn crl_this_update_future() {
        let future = 1_900_000_000u64; // year 2030+
        let der = build_signed_crl_der(&[&[0x01]], Some(future), Some(future + 86_400));
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        // "now" is 1_704_000_000, thisUpdate is 1_900_000_000, skew 300
        // 1_900_000_000 > 1_704_000_000 + 300 = 1_704_000_300
        assert_eq!(
            RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg),
            Err(CrlError::NotYetValid)
        );
    }

    #[test]
    fn crl_next_update_past() {
        let past = 1_700_000_000u64;
        let der = build_signed_crl_der(&[&[0x01]], Some(past - 86_400), Some(past));
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        // "now" is 1_704_000_000, nextUpdate is 1_700_000_000, skew 300
        // 1_704_000_000 > 1_700_000_000 + 300 = 1_700_000_300
        assert_eq!(
            RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg),
            Err(CrlError::AlreadyExpired)
        );
    }

    #[test]
    fn crl_no_next_update() {
        let now = 1_704_000_000u64;
        let fx = ca_fixture();
        // CRL with no nextUpdate, thisUpdate is now. Built by hand (not via
        // build_signed_crl_der, which always writes nextUpdate) and signed with the fixture's
        // real key so it still verifies.
        let tbs_items: Vec<Vec<u8>> = vec![
            der_enc::encode_integer(&[0x01]), // version v2
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            fx.subject_dn.clone(),
            der_enc::encode_utctime(now), // thisUpdate
            // no nextUpdate
            der_enc::encode_sequence(&[der_enc::encode_sequence(&[
                der_enc::encode_integer(&[0x01]),
                der_enc::encode_utctime(now),
            ])]),
        ];
        let der = sign_tbs_into_crl(&tbs_items, fx);

        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        assert!(parsed.next_update().is_none());
        let verified = verify_signature(parsed, &fx.issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(now), &cfg)
            .expect("build should succeed");
        // Fresh for no_next_update_ttl_secs (86_400)
        assert_eq!(idx.freshness(UnixSeconds::new(now), &cfg), Freshness::Fresh);
        assert_eq!(
            idx.freshness(UnixSeconds::new(now + 86_400), &cfg),
            Freshness::Fresh
        );
        assert_eq!(
            idx.freshness(UnixSeconds::new(now + 86_401), &cfg),
            Freshness::Stale
        );
        assert_eq!(
            idx.freshness(UnixSeconds::new(now + 172_801), &cfg),
            Freshness::Expired
        );
    }

    #[test]
    fn crl_no_next_update_already_expired_at_install_is_refused() {
        // #729 SHOULD_FIX 5: the AlreadyExpired guard in build only looked at an explicit
        // nextUpdate, so a CRL with no nextUpdate at all skipped the staleness check entirely,
        // and build returned Ok for a CRL already Expired by its own freshness() at the instant
        // of construction. Apply the same refusal using the synthetic expiry
        // (thisUpdate + no_next_update_ttl_secs) freshness() itself uses when nextUpdate is
        // absent: a CRL decades past that synthetic expiry must be refused at build time, not
        // installed and merely reported stale later.
        let fx = ca_fixture();
        let long_ago = 1_000_000_000u64; // 2001-09-09: decades before "now" below
        let tbs_items: Vec<Vec<u8>> = vec![
            der_enc::encode_integer(&[0x01]),
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            fx.subject_dn.clone(),
            der_enc::encode_utctime(long_ago), // thisUpdate
            // no nextUpdate
            der_enc::encode_sequence(&[der_enc::encode_sequence(&[
                der_enc::encode_integer(&[0x01]),
                der_enc::encode_utctime(long_ago),
            ])]),
        ];
        let der = sign_tbs_into_crl(&tbs_items, fx);

        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        assert!(parsed.next_update().is_none());
        let verified = verify_signature(parsed, &fx.issuer_der).expect("fixture CRL must verify");
        assert_eq!(
            RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg),
            Err(CrlError::AlreadyExpired)
        );
    }

    #[test]
    fn crl_generalized_time_this_update_parses() {
        // #123's design allows thisUpdate/nextUpdate to be encoded as either UTCTime or
        // GeneralizedTime (step 4d/4e); every other fixture in this module only ever encodes
        // UTCTime, leaving read_time's GeneralizedTime branch and der_enc::encode_generalized_time
        // both untested (#729 NOTE: dead code whose allow-reason documents its own uselessness).
        let fx = ca_fixture();
        let now = 1_704_000_000u64;
        let tbs_items: Vec<Vec<u8>> = vec![
            der_enc::encode_integer(&[0x01]),
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            fx.subject_dn.clone(),
            der_enc::encode_generalized_time(now), // thisUpdate as GeneralizedTime
            der_enc::encode_utctime(now + 86_400), // nextUpdate as UtcTime; mixing forms is legal
        ];
        let der = sign_tbs_into_crl(&tbs_items, fx);

        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("GeneralizedTime thisUpdate should parse");
        assert_eq!(parsed.this_update(), UnixSeconds::new(now));
        let verified = verify_signature(parsed, &fx.issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(now), &cfg)
            .expect("build should succeed");
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn crl_staleness_transitions() {
        let now = 1_704_000_000u64;
        let der = build_signed_crl_der(&[&[0x01]], Some(now - 86_400), Some(now + 86_400));
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(now), &cfg)
            .expect("build should succeed");

        // Fresh: inside nextUpdate
        assert_eq!(idx.freshness(UnixSeconds::new(now), &cfg), Freshness::Fresh);
        assert_eq!(
            idx.freshness(UnixSeconds::new(now + 86_400), &cfg),
            Freshness::Fresh
        );
        // Stale: past nextUpdate but within grace
        assert_eq!(
            idx.freshness(UnixSeconds::new(now + 86_401), &cfg),
            Freshness::Stale
        );
        assert_eq!(
            idx.freshness(UnixSeconds::new(now + 172_800), &cfg),
            Freshness::Stale
        );
        // Expired: past nextUpdate + staleGrace (86_400)
        assert_eq!(
            idx.freshness(UnixSeconds::new(now + 172_801), &cfg),
            Freshness::Expired
        );
    }

    #[test]
    fn crl_delta_refused() {
        let items: Vec<Vec<u8>> = vec![
            der_enc::encode_integer(&[0x01]), // version v2
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_name("2.5.4.3", "Test CA"),
            der_enc::encode_utctime(1_704_000_000),
            der_enc::encode_utctime(1_704_086_400),
            der_enc::encode_sequence(&[der_enc::encode_sequence(&[
                der_enc::encode_integer(&[0x01]),
                der_enc::encode_utctime(1_704_000_000),
            ])]),
            // crlExtensions [0] EXPLICIT with deltaCRLIndicator
            der_enc::encode_context_explicit(
                0,
                &der_enc::encode_sequence(&[der_enc::encode_sequence(&[
                    der_enc::encode_oid("2.5.29.27"),
                    der_enc::encode_octet_string(&[]),
                ])]),
            ),
        ];
        let tbs = der_enc::encode_sequence(&items);
        let der = der_enc::encode_sequence(&[
            tbs,
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_bit_string(&[0u8; 256]),
        ]);

        let cfg = default_cfg();
        assert_eq!(parse(&der, &cfg), Err(CrlError::DeltaCrlUnsupported));
    }

    #[test]
    fn crl_wrong_issuer() {
        // We need an actual issuer cert for verify_signature.
        // Build a minimal issuer cert.
        use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose};
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["Test CA".to_owned()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();

        // Build a CRL with a different issuer
        let items: Vec<Vec<u8>> = vec![
            der_enc::encode_integer(&[0x01]),
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_name("2.5.4.3", "Different CA"),
            der_enc::encode_utctime(1_704_000_000),
            der_enc::encode_utctime(1_704_086_400),
        ];
        let tbs = der_enc::encode_sequence(&items);
        let der = der_enc::encode_sequence(&[
            tbs,
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_bit_string(&[0u8; 256]),
        ]);

        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        assert_eq!(
            verify_signature(parsed, &cert_der),
            Err(CrlError::IssuerMismatch)
        );
    }

    #[test]
    fn crl_serials_iterator_terminates_on_invalid_entry() {
        // #729 BLOCKING 1: a revokedCertificates SEQUENCE whose content is one byte, 0xFF
        // (`30 01 FF`), is a well-formed outer TLV, but that content byte is not a valid
        // nested entry TLV on its own, so read_revoked_certificates hands the unvalidated
        // content straight to SerialIter. Before this fix, both of SerialIter::next's
        // early-error paths returned Some(Err(CrlError::Parse)) without advancing
        // self.bytes, so the iterator was never emptied and yielded Err(Parse) forever; a
        // probe drained 50,000,001 items before its own hard break stopped it. This test
        // hangs the suite on a real regression rather than merely failing: it asserts the
        // iterator is well-behaved (exactly one Err, then None) rather than bounding a
        // .count() with an external watchdog, which would still pass while the underlying
        // loop never terminates on its own.
        let mut tbs_items = vec![
            der_enc::encode_integer(&[0x01]),
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_name("2.5.4.3", "Test CA"),
            der_enc::encode_utctime(1_704_000_000),
            der_enc::encode_utctime(1_704_086_400),
        ];
        // revokedCertificates SEQUENCE with one content byte, 0xFF: `30 01 FF`. 0xFF is not a
        // valid TLV by itself (its tag byte signals a multi-byte tag form with no
        // continuation byte present), so SerialIter::next hits its tlv_bytes error path on
        // the very first call.
        tbs_items.push(vec![0x30, 0x01, 0xFF]);
        let tbs = der_enc::encode_sequence(&tbs_items);
        let der = der_enc::encode_sequence(&[
            tbs,
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_bit_string(&[0u8; 256]),
        ]);

        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("the outer shape is well-formed; parse succeeds");

        let mut serials = parsed.serials();
        assert_eq!(
            serials.next(),
            Some(Err(CrlError::Parse)),
            "the single malformed entry must surface as one Err"
        );
        assert_eq!(
            serials.next(),
            None,
            "the iterator must terminate after the error, not loop forever yielding Err(Parse)"
        );
        // Draining the whole iterator, the idiom crl_no_revoked_list and crl_single_entry
        // already use (.count()), must also terminate rather than hang.
        assert_eq!(parsed.serials().count(), 1);
    }

    #[test]
    fn crl_outer_certificate_list_tag_is_checked() {
        // The outer CertificateList wrapper's SEQUENCE tag assertion, in
        // read_sequence_content_from_reader. DER's length encoding does not depend on the tag,
        // so a reader that skipped this assertion would happily treat any constructed universal
        // tag's content as if it were a SEQUENCE's. Flip only the outer tag byte, SEQUENCE
        // (0x30) to SET (0x31), leaving the length and every nested byte untouched: without the
        // tag check this would parse identically to the unmutated CRL.
        let der = build_single_signed_crl(&[0x2a]);
        let mut mutated = der.clone();
        if let Some(byte) = mutated.get_mut(0) {
            assert_eq!(
                *byte, 0x30,
                "test fixture's outer tag is not SEQUENCE as expected"
            );
            *byte = 0x31;
        }
        assert_eq!(parse(&mutated, &default_cfg()), Err(CrlError::Parse));
    }

    #[test]
    fn crl_tbs_cert_list_tag_is_checked() {
        // #729 SURVIVED M1: read_sequence_content dropping its SEQUENCE tag assertion.
        // read_sequence_content (not the outer-only read_sequence_content_from_reader above) is
        // the function used at every OTHER structural boundary in this module: TBSCertList's
        // own content in parse_tbs_cert_list, each revoked entry's content, revokedCertificates'
        // content, crlExtensions' content, and both AlgorithmIdentifier comparisons inside
        // verify_signature. This is the structural half of the #726 fix, not the length-based
        // slicing that follows it. Flip TBSCertList's own tag byte, located via tbs_span()
        // rather than a hardcoded offset, SEQUENCE (0x30) to SET (0x31), leaving the length and
        // every nested byte untouched: without the tag check parse_tbs_cert_list would read the
        // identical content and this would parse exactly like the unmutated CRL.
        let der = build_single_signed_crl(&[0x2a]);
        let tbs_start = {
            let parsed = parse(&der, &default_cfg()).expect("should parse");
            let tbs = parsed.tbs_span();
            tbs.as_ptr() as usize - der.as_ptr() as usize
        };
        let mut mutated = der.clone();
        if let Some(byte) = mutated.get_mut(tbs_start) {
            assert_eq!(
                *byte, 0x30,
                "test fixture's TBSCertList tag is not SEQUENCE as expected"
            );
            *byte = 0x31;
        }
        assert_eq!(parse(&mutated, &default_cfg()), Err(CrlError::Parse));
    }

    #[test]
    fn crl_unsupported_version_rejected() {
        // #729 SURVIVED M26: parse_tbs_cert_list accepted any version integer. The CRL version
        // field is present only for v2 and RFC 5280 requires its value be exactly 1 (meaning
        // v2); a v1 CRL omits it entirely (crl_empty and friends never encode a version field
        // either). Any other explicit value is a version this parser does not understand, and
        // it must refuse rather than silently walk the rest of the structure as if it were v2.
        let items: Vec<Vec<u8>> = vec![
            der_enc::encode_integer(&[0x02]), // version value 2: not accepted
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_name("2.5.4.3", "Test CA"),
            der_enc::encode_utctime(1_704_000_000),
            der_enc::encode_utctime(1_704_086_400),
        ];
        let tbs = der_enc::encode_sequence(&items);
        let der = der_enc::encode_sequence(&[
            tbs,
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_bit_string(&[0u8; 256]),
        ]);
        assert_eq!(
            parse(&der, &default_cfg()),
            Err(CrlError::UnsupportedVersion)
        );
    }

    // -----------------------------------------------------------------------
    // #726 acceptance: verify_signature must accept a genuinely valid signature and reject
    // an invalid one. Every other test in this module reaches RevocationIndex::build through
    // a real verify_signature call now, but these three are the ones #726 calls out by name:
    // before the fix, verify_signature rejected every input including a real signature, so
    // "always Err" would have passed every test in this file that only ever checked an error
    // variant, and only a test that requires Ok can catch that.
    // -----------------------------------------------------------------------

    #[test]
    fn crl_verify_signature_accepts_a_genuinely_signed_crl() {
        // Mirrors fuzz_targets/fuzz_crl_parse.rs's own construction: a real RSA-2048 CA key
        // pair and a CRL built and signed through rcgen's CertificateRevocationListParams::
        // signed_by, the same mechanism the fuzz target already uses to reach this code path,
        // rather than a second hand-rolled signer. This is the test #726 says the fix is
        // unverifiable without: this module's other pre-existing tests all reached
        // RevocationIndex::build by constructing VerifiedCrl directly, so none of them would
        // ever have caught a comparison that can never match.
        use rcgen::{
            CertificateParams, CertificateRevocationListParams, Issuer, KeyIdMethod, KeyPair,
            KeyUsagePurpose, RevokedCertParams, SerialNumber,
        };
        ensure_provider_installed();

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec!["cafixture.test".to_owned()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = ca_params.self_signed(&key_pair).unwrap();
        let issuer_der = cert.der().to_vec();

        let issuer = Issuer::from_params(&ca_params, &key_pair);
        let crl_params = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2024, 1, 1),
            next_update: rcgen::date_time_ymd(2030, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from_slice(&[0x2a]),
                revocation_time: rcgen::date_time_ymd(2024, 6, 1),
                reason_code: None,
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let der = crl_params.signed_by(&issuer).unwrap().der().to_vec();

        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("a genuinely valid CRL must parse");
        let verified = verify_signature(parsed, &issuer_der)
            .expect("a CRL signed by its own stated issuer must verify");

        // 2025-01-01, inside the fixture's 2024..2030 validity window.
        let now = UnixSeconds::new(1_735_689_600);
        let idx = RevocationIndex::build(&verified, now, &cfg).expect("build should succeed");
        assert!(idx.is_revoked(&[0x2a]));
        assert!(!idx.is_revoked(&[0x2b]));
    }

    #[test]
    fn crl_verify_signature_rejects_a_different_key() {
        // The correctly signed fixture CRL, verified against a DIFFERENT CA that happens to
        // share the same subject DN (rcgen's own default: CertificateParams::new only sets
        // subject_alt_names, never distinguished_name, so every CA built this way gets the
        // same "CN=rcgen self signed cert" subject regardless of key). The issuer-name check
        // in verify_signature therefore passes, so this exercises the signature check itself,
        // not IssuerMismatch: it is what stops the fix from degenerating into "make
        // verify_signature always return Ok", which would otherwise pass every other test in
        // this module.
        use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose};

        let der = build_single_signed_crl(&[0x2a]);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");

        let other_key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let mut other_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        other_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        other_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let other_cert = other_params.self_signed(&other_key).unwrap();

        assert_eq!(
            verify_signature(parsed, other_cert.der()),
            Err(CrlError::BadSignature)
        );
    }

    #[test]
    fn crl_verify_signature_rejects_a_flipped_signature_bit() {
        // Same fixture as the rest of this module. One bit of the (real, valid) signature is
        // flipped after signing, located via parse's own borrow into the buffer (parsed.
        // signature is a subslice of the bytes we hand it) rather than a hardcoded byte
        // offset, so this does not depend on knowing the encoder's exact layout.
        let der = build_single_signed_crl(&[0x2a]);
        let cfg = default_cfg();
        let offset = {
            let parsed = parse(&der, &cfg).expect("should parse");
            parsed.signature.as_ptr() as usize - der.as_ptr() as usize
        };
        let mut mutated = der.clone();
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 0x01;
        }

        let parsed = parse(&mutated, &cfg)
            .expect("flipping one bit inside the signature content must not change the DER shape");
        assert_eq!(
            verify_signature(parsed, &ca_fixture().issuer_der),
            Err(CrlError::BadSignature)
        );
    }

    #[test]
    fn crl_inner_outer_signature_algorithm_mismatch_rejected() {
        // #729 SHOULD_FIX 4 (RFC 5280 5.1.1.2): TBSCertList's own signature AlgorithmIdentifier
        // and the outer signatureAlgorithm MUST be identical. The outer field sits outside
        // tbs_span and is therefore not covered by the signature, so an attacker who controls
        // only the outer bytes (a MITM without the issuing key) could otherwise steer which
        // algorithm verify_signature selects. Build a genuinely, validly signed CRL
        // (sha256WithRSA inner and outer), then splice in a DIFFERENT outer
        // AlgorithmIdentifier (sha384WithRSA) after signing, leaving the signed TBS bytes
        // untouched. verify_signature must reject this before it ever reaches the provider's
        // algorithm lookup, which would otherwise select sha384's verifier for a signature
        // actually computed over sha256 and simply fail as BadSignature instead: the point of
        // this guard is to reject on the mismatch itself, not rely on that downstream failure.
        let fx = ca_fixture();
        let tbs_items: Vec<Vec<u8>> = vec![
            der_enc::encode_integer(&[0x01]),
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"), // inner: sha256WithRSA
            fx.subject_dn.clone(),
            der_enc::encode_utctime(1_704_000_000),
            der_enc::encode_utctime(1_704_086_400),
        ];
        let tbs = der_enc::encode_sequence(&tbs_items);
        let signature = rcgen::SigningKey::sign(&fx.key_pair, &tbs)
            .expect("RSA signing must not fail for a well-formed TBS in a test fixture");
        let sig_value = der_enc::encode_bit_string(&signature);
        // Outer AlgorithmIdentifier differs from the inner one: sha384WithRSAEncryption.
        let outer_sig_alg = der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.12");
        let der = der_enc::encode_sequence(&[tbs, outer_sig_alg, sig_value]);

        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        assert_eq!(
            verify_signature(parsed, &fx.issuer_der),
            Err(CrlError::UnsupportedSignatureAlgorithm)
        );
    }

    #[test]
    fn crl_truncated_every_97_bytes() {
        use rcgen::{CertificateParams, KeyPair};
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["Test CA".to_owned()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).unwrap();
        let _cert_der = cert.der().to_vec();

        // Build a CRL with 1000 entries
        let serials: Vec<Vec<u8>> = (0u64..1000)
            .map(|i| {
                let bytes = i.to_be_bytes();
                // Skip leading zeros
                let start = bytes
                    .iter()
                    .position(|b| *b != 0)
                    .unwrap_or(bytes.len() - 1);
                bytes[start..].to_vec()
            })
            .collect();
        let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
        let der = build_crl_der(&serial_refs, None, None, false);

        // Truncate at every 97th byte and assert the exact Err variant, not is_err() (#729
        // SHOULD_FIX 2: `result.is_err() || result.is_ok()` is true of every Result and asserts
        // nothing beyond absence of panic). None of these truncation points can produce
        // TooManyEntries, SerialTooLong, UnsupportedVersion or DeltaCrlUnsupported (the fixture
        // has none of those shapes to truncate into), and none can equal the full, untruncated
        // length (der.len() is excluded by the range), so every truncation must fail as a
        // structural decode error.
        for end in (0..der.len()).step_by(97).skip(1) {
            let truncated = &der[..end];
            let result = parse(truncated, &default_cfg());
            assert_eq!(
                result,
                Err(CrlError::Parse),
                "truncation at {end} of {} bytes produced an unexpected result",
                der.len()
            );
        }
    }

    #[test]
    fn crl_all_ff_refused() {
        // 256 MiB of 0xFF
        let big = vec![0xffu8; 268_435_456];
        // One byte under the input length: refused by the size check before any parse
        // attempt, per edge case 4 ("max_bytes exactly and one over").
        let mut cfg_small = default_cfg();
        cfg_small.max_bytes = 268_435_455;
        assert_eq!(parse(&big, &cfg_small), Err(CrlError::TooLarge));

        // With a raised max_bytes, parse is attempted and must fail as a decode error, not an
        // OOM: 0xFF is not a valid outer SEQUENCE tag, so the walk fails on the first header it
        // reads. Assert the exact variant, not is_err() (#729 SHOULD_FIX 2).
        alloc_probe::reset();
        let result = parse(&big, &default_cfg());
        let delta = alloc_probe::bytes();
        assert_eq!(result, Err(CrlError::Parse));
        // Edge case 18: must not OOM. parse borrows the input and never copies it, so the
        // allocated-byte delta for this call must be far under twice the input length; in
        // practice it is exactly zero, since parse never allocates at all. If a future change
        // makes parse allocate, it must also call alloc_probe::record at the new site (see
        // name.rs's alloc_probe doc) or this assertion silently stops measuring anything.
        assert!(
            delta < 2 * big.len(),
            "parse allocated {delta} bytes for a {}-byte input, exceeding the 2x bound",
            big.len()
        );
    }

    #[test]
    fn crl_nested_bomb_is_fast() {
        // Build a deeply nested DER bomb: 10,000 nested SEQUENCEs
        let mut inner = vec![0x05u8, 0x00]; // NULL
        for _ in 0..10_000 {
            let mut buf = vec![0x30u8]; // SEQUENCE tag
            let len = inner.len();
            #[allow(
                clippy::cast_possible_truncation,
                reason = "len is bounded by inner.len() which is < 10000 bytes after 10000 iterations of SEQUENCE wrapping; well within u8"
            )]
            {
                if len < 128 {
                    buf.push(len as u8);
                } else {
                    // Longer encoding not needed for small bombs
                    buf.push(0x81);
                    buf.push(len as u8);
                }
            }
            buf.extend_from_slice(&inner);
            inner = buf;
        }
        let start = std::time::Instant::now();
        let result = parse(&inner, &default_cfg());
        let elapsed = start.elapsed();
        // Exact variant, not is_err() (#729 SHOULD_FIX 2). The walk reads a fixed structure and
        // never recurses into unknown content, so it never sees past the first nesting level:
        // the outer SEQUENCE's content is handed to parse_tbs_cert_list, which reads it as
        // {version?, algorithm, issuer, thisUpdate, ...} and fails as soon as it expects a
        // second sibling field that the single nested SEQUENCE does not provide.
        assert_eq!(result, Err(CrlError::Parse));
        assert!(
            elapsed.as_millis() < 100,
            "nested bomb took {} ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn crl_set_keeps_later_this_update() {
        // Both types are Send + Sync (compile-time check)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RevocationIndex>();
        assert_send_sync::<CrlSet>();

        // Build two indices for the same issuer with different thisUpdate times
        let der_early = build_signed_crl_der(&[&[0x01]], Some(1_704_000_000), Some(1_704_086_400));
        let der_late = build_signed_crl_der(&[&[0x02]], Some(1_704_000_100), Some(1_704_086_500));
        let cfg = default_cfg();

        let parsed_early = parse(&der_early, &cfg).unwrap();
        let parsed_late = parse(&der_late, &cfg).unwrap();

        let verified_early = verify_signature(parsed_early, &ca_fixture().issuer_der).unwrap();
        let verified_late = verify_signature(parsed_late, &ca_fixture().issuer_der).unwrap();

        let idx_early =
            RevocationIndex::build(&verified_early, UnixSeconds::new(1_704_000_000), &cfg).unwrap();
        let idx_late =
            RevocationIndex::build(&verified_late, UnixSeconds::new(1_704_000_000), &cfg).unwrap();

        let set = CrlSet::from_indices(vec![Arc::new(idx_early), Arc::new(idx_late)], 1);
        assert_eq!(set.len(), 1);
        let found = set.for_issuer(&ca_fixture().subject_dn).unwrap();
        // Should keep the one with later thisUpdate (serial 2)
        assert!(found.is_revoked(&[0x02]));
        assert!(!found.is_revoked(&[0x01]));
    }

    #[test]
    fn crl_for_issuer_confirms_byte_for_byte() {
        // #729 SURVIVED M20: CrlSet::for_issuer dropping its byte-for-byte issuer_dn
        // confirmation after the hash lookup. blake3(issuer_dn)[..16] is the HashMap key, so a
        // genuine hash collision would otherwise let one issuer's revocation list answer for a
        // certificate issued by someone else. A real BLAKE3 collision is infeasible to search
        // for, so simulate the shape directly: store an index built for one issuer under a
        // DIFFERENT issuer's hash (indistinguishable, at the HashMap lookup level, from a real
        // collision landing there), and confirm for_issuer for that different issuer still
        // returns None because the candidate's own issuer_dn does not match.
        let der = build_signed_crl_der(&[&[0x01]], None, None);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).unwrap();
        let verified = verify_signature(parsed, &ca_fixture().issuer_der).unwrap();
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg).unwrap();
        // idx's own issuer_dn is ca_fixture().subject_dn; store it under a different issuer's
        // hash to simulate a collision landing on that entry.
        let other_issuer_dn = b"not the fixture's issuer".as_slice();
        let mut hash = [0u8; 16];
        let full = blake3::hash(other_issuer_dn);
        if let Some(src) = full.as_bytes().get(..16) {
            hash.copy_from_slice(src);
        }
        let mut by_issuer = std::collections::HashMap::new();
        by_issuer.insert(hash, Arc::new(idx));
        let set = CrlSet {
            by_issuer,
            generation: 1,
        };
        assert!(set.for_issuer(other_issuer_dn).is_none());
    }

    #[test]
    fn crl_memory_bytes_under_20mb() {
        let cfg = default_cfg();
        // Build a CRL with 1,000,000 entries (all 8-byte serials to fit in u128)
        let serials: Vec<Vec<u8>> = (0u64..1_000_000)
            .map(|i| {
                let bytes = i.to_be_bytes();
                let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
                bytes[start..].to_vec()
            })
            .collect();
        let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
        let der = build_signed_crl_der(&serial_refs, None, None);
        let parsed = parse(&der, &cfg).expect("should parse 1M CRL");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        let bytes = idx.memory_bytes();
        assert!(bytes < 20 * 1024 * 1024, "memory_bytes {bytes} >= 20 MB");
    }

    #[test]
    fn crl_parse_1e6_allocation_bounded() {
        // Build a CRL with 1,000,000 entries and assert the ALLOCATED-BYTE DELTA of the
        // build() call itself is under 200 MB, using the thread-local counting probe in
        // name.rs's alloc_probe module (#123's acceptance criterion). This is a different and
        // stricter quantity than the final structure's own memory_bytes(), which
        // crl_memory_bytes_under_20mb already asserts on this same fixture with a 10x tighter
        // bound: memory_bytes() cannot see the transient over-allocation from Vec's doubling
        // growth strategy while push() is still running, only what survives into the final
        // boxed slices. #729 BLOCKING 3.
        let cfg = default_cfg();
        let serials: Vec<Vec<u8>> = (0u64..1_000_000)
            .map(|i| {
                let bytes = i.to_be_bytes();
                let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
                bytes[start..].to_vec()
            })
            .collect();
        let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
        let der = build_signed_crl_der(&serial_refs, None, None);
        let parsed = parse(&der, &cfg).expect("should parse 1M CRL");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        alloc_probe::reset();
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        let delta = alloc_probe::bytes();
        assert!(
            alloc_probe::count() > 0,
            "alloc_probe recorded zero events; the instrumented allocation sites in \
             RevocationIndex::build were not reached, so this assertion is not measuring \
             anything"
        );
        assert!(
            delta < 200 * 1024 * 1024,
            "allocated-byte delta {delta} >= 200 MB"
        );
        let bytes = idx.memory_bytes();
        assert!(bytes < 200 * 1024 * 1024, "memory_bytes {bytes} >= 200 MB");
    }

    // -----------------------------------------------------------------------
    // Bloom prefilter (#729 SHOULD_FIX 1: the entire subsystem shipped with no test of its
    // own; 6 of 27 total mutations run were Bloom-related and every one survived).
    // -----------------------------------------------------------------------

    #[test]
    fn crl_bloom_sizing_matches_literal_table() {
        // #729 SURVIVED M7 (BLOOM_CAP_BYTES), M8 (BLOOM_FLOOR_BYTES), M9 (BLOOM_BITS_PER_ENTRY).
        // Both #123's design note and THREAT-MODEL.md's Certificate revocation section claim
        // "10 bits per entry, floored at 2,048 bytes and capped at 4,194,304 bytes", and the
        // sizing is observable, so this table compares against LITERAL numbers this test owns,
        // not against the constants it is meant to be checking: a test that recomputed the
        // expectation from BLOOM_BITS_PER_ENTRY / BLOOM_FLOOR_BYTES / BLOOM_CAP_BYTES would
        // still pass after any of those three constants was mutated, because both sides of the
        // comparison would move together (the exact shape #721 found proved nothing in a
        // sibling crate's cap test). build_bloom is exercised directly with synthetic u128
        // vectors: only the COUNT matters to its sizing arithmetic, so this needs no CRL
        // parsing or signing.
        let cases: &[(usize, usize)] = &[
            (0, 2_048),             // floor: no entries
            (1, 2_048),             // floor: 10 bits does not clear it
            (1_000, 2_048),         // floor: 10,000 bits does not clear it either
            (100_000, 125_056),     // 1,000,000 bits, rounded up to a 512-bit block
            (1_000_000, 1_250_048), // 10,000,000 bits, rounded up; matches the issue's ~1.25 MB
            (4_000_000, 4_194_304), // 40,000,000 bits exceeds the cap; clamped to it exactly
        ];
        for &(entries, expected_bytes) in cases {
            let serials: Vec<u128> = (0..u128::try_from(entries).unwrap_or(0)).collect();
            let empty_wide: HashSet<Box<[u8]>> = HashSet::new();
            let bloom = build_bloom(&serials, &empty_wide);
            assert_eq!(
                bloom.len() * 8,
                expected_bytes,
                "entries={entries}: bloom is {} bytes, expected {expected_bytes}",
                bloom.len() * 8
            );
        }
    }

    #[test]
    fn crl_bloom_rejects_absent_serials_without_binary_search() {
        // #729 SURVIVED M11, the single most important Bloom mutation: bloom_probe
        // accumulating with OR instead of AND. Starting from `present = true` and OR-ing keeps
        // it true unconditionally (short of an out-of-bounds word, which does not happen here),
        // so a mutated bloom_probe answers "maybe present" for essentially every input,
        // silently turning every lookup into a binary search: is_revoked's boolean OUTPUT is
        // unchanged either way, because the binary search is authoritative and still returns
        // the correct answer, so a test that only checks is_revoked's return value (like
        // prop_is_revoked_matches_hashset) cannot distinguish "answered from the Bloom" from
        // "fell through to the binary search". The only externally observable signal is
        // RevocationStats::bloom_rejects, so this test probes many CLEARLY ABSENT serials and
        // asserts most of them were rejected by the prefilter alone.
        // Minimally-encoded big-endian content, the same trimming crl_memory_bytes_under_20mb
        // and crl_parse_1e6_allocation_bounded use: a DER INTEGER must not carry redundant
        // leading zero octets.
        let serials: Vec<Vec<u8>> = (1u64..=200)
            .map(|i| {
                let bytes = i.to_be_bytes();
                let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
                bytes.get(start..).unwrap_or(&bytes).to_vec()
            })
            .collect();
        let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
        let der = build_signed_crl_der(&serial_refs, None, None);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified =
            verify_signature(parsed, &ca_fixture().issuer_der).expect("fixture CRL must verify");
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");

        let before = idx.stats.bloom_rejects.load(Ordering::Relaxed);
        let probes = 1_000u64;
        for i in 0..probes {
            // Far outside the revoked set (1..=200), so every one is a true negative.
            let probe = (1_000_000 + i).to_be_bytes();
            assert!(
                !idx.is_revoked(&probe),
                "probe {} must not be revoked",
                1_000_000 + i
            );
        }
        let after = idx.stats.bloom_rejects.load(Ordering::Relaxed);
        let rejected = after - before;
        assert!(
            rejected > 0,
            "no lookups were rejected by the Bloom filter alone; with OR-accumulation \
             (mutation M11) this reads 0 because every probe falls through to the binary search \
             instead"
        );
        // At 10 bits per entry and k = 7, #123's design states a false-positive rate under
        // 0.1% at this load factor (r = 200, well below the 2,048-byte floor's break-even
        // point), so the overwhelming majority of 1,000 clearly absent probes must be rejected
        // by the prefilter alone. A generous 90% floor comfortably separates "the prefilter
        // works" from "the prefilter never rejects anything" without being sensitive to the
        // exact false-positive rate.
        assert!(
            rejected >= probes * 9 / 10,
            "bloom filter rejected only {rejected} of {probes} clearly absent probes"
        );
    }

    #[test]
    fn crl_build_bloom_inserts_wide_serials() {
        // #729 SURVIVED M12: build_bloom never inserting wide serials into the filter.
        // is_revoked's wide-length path returns from the overflow HashSet before ever probing
        // the Bloom (design: "Wide serials skip the Bloom filter"), so this insertion has no
        // effect reachable through the public API; that is exactly why the mutation survived
        // every other test in this module. Assert build_bloom's own output directly: filling it
        // with a wide serial present must set bits a fill without it does not.
        let narrow: Vec<u128> = Vec::new();
        let mut wide: HashSet<Box<[u8]>> = HashSet::new();
        wide.insert(vec![0xAAu8; 17].into_boxed_slice());
        let without_wide = build_bloom(&narrow, &HashSet::new());
        let with_wide = build_bloom(&narrow, &wide);
        assert_ne!(
            without_wide, with_wide,
            "build_bloom must set bits for wide serials per #123's build algorithm step 3 \
             (fill from the deduplicated set of BOTH containers), even though is_revoked never \
             probes them for a wide-length lookup"
        );
    }

    // -----------------------------------------------------------------------
    // Property tests
    // -----------------------------------------------------------------------

    proptest! {
        #[test]
        fn prop_is_revoked_matches_hashset(
            serials in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 1..=20usize),
                1..=200,
            ),
            probes in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 1..=20usize),
                100,
            ),
        ) {
            let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
            if serial_refs.len() > 8_000_000 {
                return Ok(());
            }
            let der = build_signed_crl_der(&serial_refs, None, None);
            let cfg = default_cfg();
            let Ok(parsed) = parse(&der, &cfg) else {
                return Ok(());
            };
            let verified = verify_signature(parsed, &ca_fixture().issuer_der)
                .expect("a CRL signed by ca_fixture's own key must always verify");
            let Ok(idx) = RevocationIndex::build(
                &verified,
                UnixSeconds::new(1_704_000_000),
                &cfg,
            ) else {
                return Ok(());
            };

            let mut reference: HashSet<Vec<u8>> = HashSet::new();
            for s in &serials {
                let norm = normalize_serial(s).to_vec();
                reference.insert(norm);
            }

            // Assert every serial in the index is matched
            for s in &serials {
                let found = idx.is_revoked(s);
                let norm = normalize_serial(s).to_vec();
                let expected = reference.contains(&norm);
                prop_assert_eq!(found, expected, "serial {:?} (normalized {:?}) mismatch", s, norm);
            }

            // Assert random probes agree
            for probe in &probes {
                let found = idx.is_revoked(probe);
                let norm = normalize_serial(probe).to_vec();
                let expected = reference.contains(&norm);
                prop_assert_eq!(found, expected, "probe {:?} (normalized {:?}) mismatch", probe, norm);
            }
        }

        #[test]
        fn prop_serial_normalization_is_stable(
            base in proptest::collection::vec(any::<u8>(), 1..=16usize),
            extra_leading_zeros in 0..=8usize,
        ) {
            // Build with the base serial, then look up with leading zeros added.
            // They should match.
            let der = build_single_signed_crl(&base);
            let cfg = default_cfg();
            let Ok(parsed) = parse(&der, &cfg) else {
                return Ok(());
            };
            let verified = verify_signature(parsed, &ca_fixture().issuer_der)
                .expect("a CRL signed by ca_fixture's own key must always verify");
            let Ok(idx) = RevocationIndex::build(
                &verified,
                UnixSeconds::new(1_704_000_000),
                &cfg,
            ) else {
                return Ok(());
            };

            // Look up with extra leading zeros
            let mut padded = vec![0x00u8; extra_leading_zeros];
            padded.extend_from_slice(&base);
            prop_assert!(idx.is_revoked(&base));
            prop_assert!(idx.is_revoked(&padded));
        }

        #[test]
        fn prop_parse_never_panics(
            valid_crl_der in proptest::collection::vec(any::<u8>(), 50..=2000usize),
            flip_offset in 0..2000usize,
        ) {
            // parse must never panic on arbitrary random byte sequences, regardless of shape.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                parse(&valid_crl_der, &default_cfg())
            }));
            prop_assert!(result.is_ok(), "parse must not panic on random byte sequences");

            // parse must never panic on a single flipped byte anywhere in an otherwise
            // well-formed (unsigned) CRL either.
            let base_der = build_crl_der(&[&[0x01], &[0x02]], None, None, false);
            if flip_offset < base_der.len() {
                let mut corrupted = base_der;
                if let Some(byte) = corrupted.get_mut(flip_offset) {
                    *byte ^= 0xff;
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    parse(&corrupted, &default_cfg())
                }));
                prop_assert!(
                    result.is_ok(),
                    "parse must not panic on any input; flipped byte at offset {flip_offset}"
                );
            }

            // Anti-splicing property (#123's own property spec; #729 SHOULD_FIX 3). Flip one
            // byte STRICTLY INSIDE the signed TBS span of a genuinely, validly signed CRL. If
            // parse still returns Ok after the flip, the flip must have broken the signature,
            // because the flipped byte is inside the region verify_signature hashes. A flip
            // landing in an unauthenticated trailing region (the outer signatureAlgorithm or
            // the signature bytes themselves) could still verify, which is why the flip is
            // restricted to tbs_span rather than the whole blob.
            let signed_der = build_single_signed_crl(&[0x2a]);
            let (tbs_start, tbs_len) = {
                let parsed =
                    parse(&signed_der, &default_cfg()).expect("the signed fixture CRL must parse");
                let tbs = parsed.tbs_span();
                (
                    tbs.as_ptr() as usize - signed_der.as_ptr() as usize,
                    tbs.len(),
                )
            };
            if tbs_len > 0 {
                let offset_in_tbs = flip_offset % tbs_len;
                let mut spliced = signed_der.clone();
                if let Some(byte) = spliced.get_mut(tbs_start + offset_in_tbs) {
                    *byte ^= 0xff;
                }
                let flip_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    parse(&spliced, &default_cfg())
                }));
                prop_assert!(
                    flip_result.is_ok(),
                    "parse must not panic on a flipped byte inside the TBS span"
                );
                if let Ok(Ok(parsed)) = flip_result {
                    let verified = verify_signature(parsed, &ca_fixture().issuer_der);
                    prop_assert!(
                        verified.is_err(),
                        "flipping a byte inside the TBS span must break the signature, but \
                         verify_signature returned Ok"
                    );
                }
            }
        }
    }

    // Test-only accessor for the private wide set, used by
    // crl_serial_leading_zero_16_bytes to confirm a 16-byte-after-normalization serial did
    // NOT go into the overflow set.
    impl RevocationIndex {
        fn wide(&self) -> &HashSet<Box<[u8]>> {
            &self.wide
        }
    }
}
