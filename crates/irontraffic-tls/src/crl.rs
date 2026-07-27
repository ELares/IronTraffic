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
        while !self.bytes.is_empty() {
            let mut reader = match der::SliceReader::new(self.bytes) {
                Ok(r) => r,
                Err(_) => return Some(Err(CrlError::Parse)),
            };
            let entry_tlv = match reader.tlv_bytes() {
                Ok(tlv) => tlv,
                Err(_) => return Some(Err(CrlError::Parse)),
            };
            let consumed = entry_tlv.len();
            self.bytes = match self.bytes.get(consumed..) {
                Some(rest) => rest,
                None => return Some(Err(CrlError::Parse)),
            };

            let serial = match serial_from_entry(entry_tlv) {
                Ok(s) => s,
                Err(e) => return Some(Err(e)),
            };
            return Some(Ok(serial));
        }
        None
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
    let header = reader.peek_header().map_err(|_| CrlError::Parse)?;
    if header.tag == der::Tag::UtcTime || header.tag == der::Tag::GeneralizedTime {
        Ok(Some(read_time(reader)?))
    } else {
        Ok(None)
    }
}

fn read_revoked_certificates<'a>(reader: &mut der::SliceReader<'a>) -> Result<&'a [u8], CrlError> {
    let header = reader.peek_header().map_err(|_| CrlError::Parse)?;
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
        if verified.this_update().get().saturating_add(skew) < now.get() {
            // thisUpdate is in the future beyond skew.
            return Err(CrlError::NotYetValid);
        }

        if let Some(next) = verified.next_update() {
            if next.get().saturating_add(skew) < now.get() {
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
    if let Some(slice) = out.get_mut(start..) {
        let take = slice.len().min(serial.len());
        if let Some(target) = slice.get_mut(..take) {
            if let Some(source) = serial.get(serial.len().saturating_sub(take)..) {
                target.copy_from_slice(source);
            }
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
        .max(BLOOM_FLOOR_BYTES * 8)
        .min(BLOOM_CAP_BYTES * 8);
    // Round bits up to a multiple of 512 (one block).
    let bits = ((bits + 511) / 512) * 512;
    let words = bits / 64;
    let mut bloom = vec![0u64; words];
    let blocks = u64::try_from(words / (BLOOM_BLOCK_BYTES / 8)).unwrap_or(1);

    for packed in serials {
        bloom_insert(&mut bloom, blocks, *packed);
    }
    for serial in wide {
        let mut buf = [0u8; 16];
        let len = serial.len().min(16);
        if let Some(src) = serial.get(..len) {
            if let Some(dst) = buf.get_mut(16 - len..) {
                dst.copy_from_slice(src);
            }
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

    #[test]
    fn crl_empty() {
        let cfg = CrlConfig::default();
        assert_eq!(parse(&[], &cfg), Err(CrlError::Empty));
    }
}
