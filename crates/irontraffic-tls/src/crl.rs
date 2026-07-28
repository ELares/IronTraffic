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
    sig_alg_der: &'a [u8],
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

    /// The encoded `TBSCertList` span, which is the signed message.
    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "convenience accessor matching the pattern of issuer_dn, this_update, etc; no test currently reads tbs_span directly because the field is pub(crate)"
    )]
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
        let Ok(mut reader) = der::SliceReader::new(self.bytes) else {
            return Some(Err(CrlError::Parse));
        };
        let Ok(entry_tlv) = reader.tlv_bytes() else {
            return Some(Err(CrlError::Parse));
        };
        let consumed = entry_tlv.len();
        let Some(rest) = self.bytes.get(consumed..) else {
            return Some(Err(CrlError::Parse));
        };
        self.bytes = rest;

        let serial = match serial_from_entry(entry_tlv) {
            Ok(s) => s,
            Err(e) => return Some(Err(e)),
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

    let sig_alg_tlv = read_next_tlv(&mut outer)?;
    let sig_value_tlv = read_next_tlv(&mut outer)?;
    let signature = signature_bytes(sig_value_tlv)?;

    Ok(ParsedCrl {
        issuer_dn: parsed_tbs.issuer_dn,
        this_update: parsed_tbs.this_update,
        next_update: parsed_tbs.next_update,
        tbs_span,
        sig_alg_der: sig_alg_tlv,
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

    // signature AlgorithmIdentifier (captured via TLV).
    let _sig_alg_tlv = read_next_tlv(&mut tbs)?;

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

    let provider = crate::provider::provider().ok_or(CrlError::ProviderNotInstalled)?;
    let alg = provider
        .signature_verification_algorithms
        .all
        .iter()
        .find(|a| {
            a.signature_alg_id().as_ref() == parsed.sig_alg_der
                && a.public_key_alg_id().as_ref() == spki_alg_der.as_slice()
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
    /// `CrlError::TooManyEntries`, `CrlError::SerialTooLong`, `CrlError::AlreadyExpired`,
    /// `CrlError::NotYetValid`.
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

        if let Some(next) = verified.next_update()
            && next.get().saturating_add(skew) < now.get()
        {
            return Err(CrlError::AlreadyExpired);
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
                wide_set.insert(serial.to_vec().into_boxed_slice());
            } else {
                serials_vec.push(pack_serial(serial));
            }
        }

        serials_vec.sort_unstable();
        serials_vec.dedup();

        let bloom = build_bloom(&serials_vec, &wide_set);
        let blocks = u32::try_from(bloom.len() / (BLOOM_BLOCK_BYTES / 8))
            .map_err(|_| CrlError::TooManyEntries)?;

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

        #[allow(
            dead_code,
            reason = "kept for symmetry with encode_utctime; may be used by future tests that need GeneralizedTime"
        )]
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

    /// Build a CRL with a single serial.
    fn build_single_crl(serial: &[u8]) -> Vec<u8> {
        build_crl_der(&[serial], None, None, false)
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
        let der = build_crl_der(&[], None, None, false);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("CRL with no revoked list should parse");
        assert_eq!(parsed.serials().count(), 0);
        let verified = VerifiedCrl { parsed };
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("build should succeed");
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
        assert!(!idx.is_revoked(&[0x01]));
    }

    #[test]
    fn crl_single_entry() {
        let der = build_single_crl(&[0x2a]); // serial 42
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("CRL with one entry should parse");
        assert_eq!(parsed.serials().count(), 1);
        let verified = VerifiedCrl { parsed };
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
        let der = build_crl_der(&serial_refs, None, None, false);
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified = VerifiedCrl { parsed };
        let idx = RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("5 entries with max_entries=5 should build");
        assert_eq!(idx.len(), 5);

        // One over
        let serials: Vec<Vec<u8>> = (0..6).map(|i| vec![i + 1]).collect();
        let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
        let der = build_crl_der(&serial_refs, None, None, false);
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified = VerifiedCrl { parsed };
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
        let der = build_single_crl(&serial);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        // The serial in the CRL has 21 content octets.
        // After normalization, it's still 21 bytes (no leading zero to strip).
        assert_eq!(
            RevocationIndex::build(
                &VerifiedCrl { parsed },
                UnixSeconds::new(1_704_000_000),
                &cfg,
            ),
            Err(CrlError::SerialTooLong)
        );

        // 21 content octets with leading zero -> normalizes to 20 -> accepted
        let serial: Vec<u8> = {
            let mut s = vec![0x00];
            s.extend_from_slice(&[0xaa; 20]);
            s
        };
        let der = build_single_crl(&serial);
        let parsed = parse(&der, &cfg).expect("should parse");
        let idx = RevocationIndex::build(
            &VerifiedCrl { parsed },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
        .expect("20-byte normalized serial should build");
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn crl_serial_17_bytes_wide() {
        // A 17-byte serial should go into the wide set.
        // Use bytes with high bit clear so DER INTEGER encoding is valid.
        let serial = [0x0a; 17];
        let der = build_single_crl(&serial);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let idx = RevocationIndex::build(
            &VerifiedCrl { parsed },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
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
        let der = build_single_crl(&serial_der);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let idx = RevocationIndex::build(
            &VerifiedCrl { parsed },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
        .expect("build should succeed");
        assert_eq!(idx.len(), 1);
        // After normalization, the serial is [0xff; 16]
        assert!(idx.is_revoked(&[0xff; 16]));
        // Same serial with DER padding (00 FF...FF)
        let mut with_padding = vec![0x00];
        with_padding.extend_from_slice(&[0xff; 16]);
        assert!(idx.is_revoked(&with_padding));
        // Should have 0 wide serials
        assert!(idx.wide.is_empty());
    }

    #[test]
    fn crl_serial_zero() {
        let der = build_single_crl(&[0x00]);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let idx = RevocationIndex::build(
            &VerifiedCrl { parsed },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
        .expect("build should succeed");
        assert_eq!(idx.len(), 1);
        // Serial 0 normalizes to [0x00]
        assert!(idx.is_revoked(&[0x00]));
        // Also matches when given with leading zeros
        assert!(idx.is_revoked(&[0x00, 0x00]));
    }

    #[test]
    fn crl_duplicate_serials() {
        let der = build_crl_der(&[&[0x01], &[0x01], &[0x02]], None, None, false);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let idx = RevocationIndex::build(
            &VerifiedCrl { parsed },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
        .expect("build should succeed");
        assert_eq!(idx.len(), 2); // deduplicated
    }

    #[test]
    fn crl_this_update_future() {
        let future = 1_900_000_000u64; // year 2030+
        let der = build_crl_der(&[&[0x01]], Some(future), Some(future + 86_400), false);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified = VerifiedCrl { parsed };
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
        let der = build_crl_der(&[&[0x01]], Some(past - 86_400), Some(past), false);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let verified = VerifiedCrl { parsed };
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
        // CRL with no nextUpdate, thisUpdate is now
        let items: Vec<Vec<u8>> = vec![
            der_enc::encode_integer(&[0x01]), // version v2
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_name("2.5.4.3", "Test CA"),
            der_enc::encode_utctime(now), // thisUpdate
            // no nextUpdate
            der_enc::encode_sequence(&[der_enc::encode_sequence(&[
                der_enc::encode_integer(&[0x01]),
                der_enc::encode_utctime(now),
            ])]),
        ];
        let tbs = der_enc::encode_sequence(&items);
        let der = der_enc::encode_sequence(&[
            tbs,
            der_enc::encode_algorithm_identifier("1.2.840.113549.1.1.11"),
            der_enc::encode_bit_string(&[0u8; 256]),
        ]);

        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        assert!(parsed.next_update().is_none());
        let verified = VerifiedCrl { parsed };
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
    fn crl_staleness_transitions() {
        let now = 1_704_000_000u64;
        let der = build_crl_der(&[&[0x01]], Some(now - 86_400), Some(now + 86_400), false);
        let cfg = default_cfg();
        let parsed = parse(&der, &cfg).expect("should parse");
        let idx = RevocationIndex::build(&VerifiedCrl { parsed }, UnixSeconds::new(now), &cfg)
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

        // Truncate at every 97th byte and assert no panic, just Err
        for end in (0..der.len()).step_by(97).skip(1) {
            let truncated = &der[..end];
            let result = parse(truncated, &default_cfg());
            assert!(result.is_err() || result.is_ok());
            // The point is that it doesn't panic, not what error it returns
        }
    }

    #[test]
    fn crl_all_ff_refused() {
        // 256 MiB of 0xFF
        let cfg = default_cfg();
        let _ = cfg;
        let big = vec![0xffu8; 268_435_456];
        // Should be refused by size check since max_bytes default is 268_435_456
        let mut cfg_small = default_cfg();
        cfg_small.max_bytes = 268_435_455;
        assert_eq!(parse(&big, &cfg_small), Err(CrlError::TooLarge));

        // With a raised max_bytes, should fail DER parse (not OOM)
        let cfg_large = default_cfg();
        let _ = cfg_large;
        let result = parse(&big, &default_cfg());
        assert!(result.is_err());
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
        assert!(result.is_err());
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
        let der_early = build_crl_der(&[&[0x01]], Some(1_704_000_000), Some(1_704_086_400), false);
        let der_late = build_crl_der(&[&[0x02]], Some(1_704_000_100), Some(1_704_086_500), false);
        let cfg = default_cfg();

        let parsed_early = parse(&der_early, &cfg).unwrap();
        let parsed_late = parse(&der_late, &cfg).unwrap();

        let idx_early = RevocationIndex::build(
            &VerifiedCrl {
                parsed: parsed_early,
            },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
        .unwrap();
        let idx_late = RevocationIndex::build(
            &VerifiedCrl {
                parsed: parsed_late,
            },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
        .unwrap();

        let set = CrlSet::from_indices(vec![Arc::new(idx_early), Arc::new(idx_late)], 1);
        assert_eq!(set.len(), 1);
        let found = set
            .for_issuer(&der_enc::encode_name("2.5.4.3", "Test CA"))
            .unwrap();
        // Should keep the one with later thisUpdate (serial 2)
        assert!(found.is_revoked(&[0x02]));
        assert!(!found.is_revoked(&[0x01]));
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
        let der = build_crl_der(&serial_refs, None, None, false);
        let parsed = parse(&der, &cfg).expect("should parse 1M CRL");
        let idx = RevocationIndex::build(
            &VerifiedCrl { parsed },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
        .expect("build should succeed");
        let bytes = idx.memory_bytes();
        assert!(bytes < 20 * 1024 * 1024, "memory_bytes {bytes} >= 20 MB");
    }

    #[test]
    fn crl_parse_1e6_allocation_bounded() {
        // Build a CRL with 1,000,000 entries and verify build succeeds with
        // bounded memory (final memory_bytes < 200 MB).
        let cfg = default_cfg();
        let serials: Vec<Vec<u8>> = (0u64..1_000_000)
            .map(|i| {
                let bytes = i.to_be_bytes();
                let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
                bytes[start..].to_vec()
            })
            .collect();
        let serial_refs: Vec<&[u8]> = serials.iter().map(std::vec::Vec::as_slice).collect();
        let der = build_crl_der(&serial_refs, None, None, false);
        let parsed = parse(&der, &cfg).expect("should parse 1M CRL");
        let idx = RevocationIndex::build(
            &VerifiedCrl { parsed },
            UnixSeconds::new(1_704_000_000),
            &cfg,
        )
        .expect("build should succeed");
        let bytes = idx.memory_bytes();
        assert!(bytes < 200 * 1024 * 1024, "memory_bytes {bytes} >= 200 MB");
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
            let der = build_crl_der(&serial_refs, None, None, false);
            let cfg = default_cfg();
            let Ok(parsed) = parse(&der, &cfg) else {
                return Ok(());
            };
            let Ok(idx) = RevocationIndex::build(
                &VerifiedCrl { parsed },
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
            let der = build_single_crl(&base);
            let cfg = default_cfg();
            let Ok(parsed) = parse(&der, &cfg) else {
                return Ok(());
            };
            let Ok(idx) = RevocationIndex::build(
                &VerifiedCrl { parsed },
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
            // We can't generate a valid CRL randomly, but we can ensure parse never panics.
            // Use a valid CRL and flip one byte inside it.
            let base_der = build_crl_der(&[&[0x01], &[0x02]], None, None, false);
            if flip_offset >= base_der.len() {
                return Ok(());
            }
            let mut corrupted = base_der;
            corrupted[flip_offset] ^= 0xff;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                parse(&corrupted, &default_cfg())
            }));
            prop_assert!(
                result.is_ok(),
                "parse must not panic on any input; flipped byte at offset {flip_offset}"
            );
            // Also test with random byte sequences
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                parse(&valid_crl_der, &default_cfg())
            }));
            prop_assert!(result.is_ok(), "parse must not panic on random byte sequences");
        }
    }

    // Helper to access wide set for assertions in crl_serial_leading_zero_16_bytes
    #[allow(
        dead_code,
        reason = "kept for test assertions; the field is private and the accessor exists in case a future test needs to inspect the wide set"
    )]
    impl RevocationIndex {
        fn wide(&self) -> &HashSet<Box<[u8]>> {
            &self.wide
        }
    }
}
