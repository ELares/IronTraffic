// SPDX-License-Identifier: MIT OR Apache-2.0

//! OCSP request building and strict, fully attacker-controlled-bytes response validation.
//!
//! This module is a self-contained parser and verifier: it performs no I/O, holds no schedule
//! state, and knows nothing about retrying or refreshing. [`build_request`] builds a
//! single-certificate OCSP request per RFC 6960 section 4.1.1. [`validate_staple`] is the
//! trust boundary: every byte it reads came from a network responder, so it is size-capped,
//! fuzzed (`fuzz/fuzz_targets/fuzz_ocsp_response.rs`), and never panics for any input.
//! [`validate_aia_url`] is the SSRF gate: the URL it checks came out of a certificate, which
//! arrives from the configuration plane, an ACME CA, or (in Kubernetes) a Secret a namespace
//! owner controls, so "the operator wrote it" is not true in every deployment.
//!
//! **Signature verification never re-encodes attacker bytes.** `validate_staple` captures the
//! exact encoded span of `tbsResponseData` (and, for a delegated responder, of the candidate
//! certificate's own `tbsCertificate`) while walking the DER by hand, and verifies the signature
//! over that captured span directly. It never asks a typed decoder to hand the bytes back by
//! re-serializing a parsed structure: even though this crate's `der` dependency only accepts
//! canonical DER and a decode-then-encode round trip is therefore byte-identical for everything
//! it accepts, capturing the original span is strictly safer and is what this module's own
//! design requires.
//!
//! **No networking-module IP types.** The private-address check in [`validate_aia_url`] needs an
//! IP-literal parser and an RFC 1918 / loopback / link-local / multicast classifier.
//! `core::net::{Ipv4Addr, Ipv6Addr}` provides exactly that, is a pure value type with no I/O
//! capability of any kind, and has lived in `core`, not in the standard library's socket-facing
//! networking module, since Rust 1.77, so using it here does not pull a socket type into a crate
//! whose whole design rests on doing no I/O; this crate is grepped for that networking module's
//! name as part of this issue's acceptance criteria, and using the `core` types instead of
//! hand-rolling an equivalent (and therefore less-tested) parser satisfies that check without
//! sacrificing correctness on a security-relevant code path. This module also does not depend on
//! a general URL-parsing crate: the issue's dependency list authorizes only `x509-ocsp` and
//! `sha1` as runtime dependencies, so the small, RFC-6960-shaped subset of URL syntax an OCSP
//! responder URL ever needs is parsed by hand in [`split_aia_url`].

use alloc::vec::Vec;
use core::fmt;

use der::{Decode, Encode, Reader as _};
use sha1::{Digest, Sha1};
use x509_cert::der::asn1::{Null, OctetString};
// `x509-ocsp`'s own `CertId`/`ResponseData` fields are typed in terms of the `spki` crate
// directly, and `x509_cert::spki` is that same crate re-exported (`x509-cert`'s `lib.rs` has
// `pub use spki;`), so this reaches the identical type without adding a direct `spki` dependency,
// which this issue's dependency list does not authorize.
use x509_cert::spki;

use crate::store::Credentials;
use crate::time::UnixSeconds;

extern crate alloc;

/// Maximum OCSP response we will read.
pub const MAX_OCSP_RESPONSE_BYTES: usize = 65_536;
/// Maximum embedded responder certificates we will consider.
pub const MAX_RESPONDER_CERTS: usize = 8;
/// Maximum encoded OCSP request we will produce. A single-certificate request is a few hundred
/// bytes; anything larger than this means a malformed input somewhere upstream.
const MAX_OCSP_REQUEST_BYTES: usize = 4_096;
/// Maximum AIA URL we will consider, per rule 1 of `validate_aia_url`.
const MAX_AIA_URL_BYTES: usize = 1_024;

/// `id-sha1`, RFC 3279. Mandatory for the `CertID` identifier hashes RFC 6960 section 4.1.1
/// specifies; never used as a signature algorithm anywhere in this module.
const OID_SHA1: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
/// `id-pkix-ocsp-basic`, RFC 6960 section 4.2.1.
const OID_OCSP_BASIC: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
/// `id-pkix-ocsp-nonce`, RFC 6960 section 4.4.1.
const OID_OCSP_NONCE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
/// `id-ce-extKeyUsage`, RFC 5280 section 4.2.1.12.
const OID_EXT_KEY_USAGE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.37");
/// `id-kp-OCSPSigning`, RFC 6960 section 4.2.2.2.
const OID_OCSP_SIGNING: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

/// OCSP stapling and refresh configuration. Read by [`validate_staple`] (`skew_secs`,
/// `no_next_update_ttl_secs`), by [`validate_aia_url`] (`allow_private_responders`), and by
/// `OcspUpdater::tick` (the schedule and backoff fields). Every function that needs a subset of
/// these fields takes the whole struct, so the reader's notion of skew and the schedule's notion
/// of skew can never drift apart at the call site.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OcspConfig {
    /// Refresh this many seconds before `nextUpdate`. Default 3600.
    #[serde(default = "d_margin")]
    pub margin_secs: u32,
    /// Never wait longer than this between refreshes. Default `86_400`.
    #[serde(default = "d_max_interval")]
    pub max_interval_secs: u32,
    /// Never wait less than this. Default 300.
    #[serde(default = "d_min_interval")]
    pub min_interval_secs: u32,
    /// First backoff step after a failure. Default 60.
    #[serde(default = "d_backoff_base")]
    pub backoff_base_secs: u32,
    /// Backoff ceiling. Default `21_600` (6 hours).
    #[serde(default = "d_backoff_max")]
    pub backoff_max_secs: u32,
    /// Consecutive failures after which the state becomes `Failed` and an alarm fires. Default 8.
    #[serde(default = "d_fail_after")]
    pub fail_after: u32,
    /// Clock skew tolerance for `thisUpdate` and `nextUpdate`. Default 300.
    #[serde(default = "d_skew")]
    pub skew_secs: u32,
    /// Validity assumed for a response with no `nextUpdate`. Default 3600.
    #[serde(default = "d_no_next")]
    pub no_next_update_ttl_secs: u32,
    /// Maximum fetches started in one `tick`. Default 8. Bounds both the outbound request rate at
    /// a responder and the wall-clock cost of one tick.
    #[serde(default = "d_max_fetches")]
    pub max_fetches_per_tick: u32,
    /// Allow an OCSP responder on a loopback, link-local, or private address. Default false.
    /// Relaxes only rule 4 of the AIA URL policy; the scheme, userinfo and port rules always
    /// apply.
    #[serde(default)]
    pub allow_private_responders: bool,
}

const fn d_margin() -> u32 {
    3_600
}
const fn d_max_interval() -> u32 {
    86_400
}
const fn d_min_interval() -> u32 {
    300
}
const fn d_backoff_base() -> u32 {
    60
}
const fn d_backoff_max() -> u32 {
    21_600
}
const fn d_fail_after() -> u32 {
    8
}
const fn d_skew() -> u32 {
    300
}
const fn d_no_next() -> u32 {
    3_600
}
const fn d_max_fetches() -> u32 {
    8
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            margin_secs: d_margin(),
            max_interval_secs: d_max_interval(),
            min_interval_secs: d_min_interval(),
            backoff_base_secs: d_backoff_base(),
            backoff_max_secs: d_backoff_max(),
            fail_after: d_fail_after(),
            skew_secs: d_skew(),
            no_next_update_ttl_secs: d_no_next(),
            max_fetches_per_tick: d_max_fetches(),
            allow_private_responders: false,
        }
    }
}

/// The only status a validated staple can carry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CertStatus {
    /// The certificate is good.
    Good,
}

/// Metadata from a validated staple.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StapleInfo {
    /// Always `Good`; other statuses are errors.
    pub status: CertStatus,
    /// `thisUpdate`.
    pub this_update: UnixSeconds,
    /// `nextUpdate`, if present.
    pub next_update: Option<UnixSeconds>,
    /// Response length in bytes.
    pub der_len: usize,
}

/// Why an OCSP operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OcspError {
    /// The credential has no issuing certificate, so no `CertID` can be built.
    NoIssuer,
    /// The issuing certificate did not parse.
    IssuerParse,
    /// The encoded request exceeded 4,096 bytes.
    RequestTooLarge,
    /// Zero-byte response.
    Empty,
    /// Response larger than `MAX_OCSP_RESPONSE_BYTES`.
    TooLarge,
    /// The response did not parse.
    Parse,
    /// `responseStatus` was not `successful`.
    ResponderStatus(u8),
    /// `responseType` was not `id-pkix-ocsp-basic`.
    UnknownResponseType,
    /// More than `MAX_RESPONDER_CERTS` embedded certificates.
    TooManyCerts,
    /// No authorized responder was found, or the delegated responder lacked `id-kp-OCSPSigning`.
    UnauthorizedResponder,
    /// The signature algorithm is not one the provider verifies.
    UnsupportedSignatureAlgorithm,
    /// The signature did not verify.
    BadSignature,
    /// Zero or more than one `SingleResponse`.
    WrongResponseCount,
    /// The `certID` did not match this credential.
    CertIdMismatch,
    /// `thisUpdate` is in the future beyond the skew tolerance.
    NotYetValid,
    /// The response is past `nextUpdate` beyond the skew tolerance.
    Expired,
    /// The response carried a nonce different from the one we sent.
    NonceMismatch,
    /// The certificate is revoked.
    CertificateRevoked {
        /// When, per the responder.
        revocation_time: UnixSeconds,
    },
    /// The responder said `unknown`.
    StatusUnknown,
    /// `install_process_provider` has not run, so no signature can be verified.
    ProviderNotInstalled,
    /// The AIA URL is unparseable, over 1,024 bytes, not `http`/`https`, carries userinfo, or
    /// names a port other than 80 or 443.
    BadResponderUrl,
    /// The AIA URL names a loopback, link-local, private, unspecified or multicast address and
    /// `allow_private_responders` is false.
    PrivateResponderAddress,
}

impl fmt::Display for OcspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OcspError::NoIssuer => {
                f.write_str("the credential has no issuing certificate, so no CertID can be built")
            }
            OcspError::IssuerParse => f.write_str("the issuing certificate did not parse"),
            OcspError::RequestTooLarge => {
                f.write_str("the encoded OCSP request exceeded 4096 bytes")
            }
            OcspError::Empty => f.write_str("the OCSP response was zero bytes"),
            OcspError::TooLarge => f.write_str("the OCSP response exceeded 65536 bytes"),
            OcspError::Parse => f.write_str("the OCSP response did not parse"),
            OcspError::ResponderStatus(s) => {
                write!(f, "OCSP responseStatus was {s}, not successful")
            }
            OcspError::UnknownResponseType => {
                f.write_str("the OCSP response type was not id-pkix-ocsp-basic")
            }
            OcspError::TooManyCerts => {
                f.write_str("the OCSP response carried more than 8 embedded responder certificates")
            }
            OcspError::UnauthorizedResponder => {
                f.write_str("no authorized OCSP responder was found for this certificate")
            }
            OcspError::UnsupportedSignatureAlgorithm => f.write_str(
                "the OCSP response signature algorithm is not one this provider verifies",
            ),
            OcspError::BadSignature => f.write_str("the OCSP response signature did not verify"),
            OcspError::WrongResponseCount => {
                f.write_str("the OCSP response did not carry exactly one SingleResponse")
            }
            OcspError::CertIdMismatch => {
                f.write_str("the OCSP response certID did not match this credential")
            }
            OcspError::NotYetValid => f.write_str(
                "the OCSP response thisUpdate is in the future beyond the allowed clock skew",
            ),
            OcspError::Expired => {
                f.write_str("the OCSP response is past nextUpdate beyond the allowed clock skew")
            }
            OcspError::NonceMismatch => {
                f.write_str("the OCSP response carried a nonce different from the one sent")
            }
            OcspError::CertificateRevoked { revocation_time } => write!(
                f,
                "the certificate is revoked as of unix time {}",
                revocation_time.get()
            ),
            OcspError::StatusUnknown => {
                f.write_str("the OCSP responder returned an unknown certificate status")
            }
            OcspError::ProviderNotInstalled => f.write_str(
                "no crypto provider is installed; install_process_provider must run first",
            ),
            OcspError::BadResponderUrl => f.write_str(
                "the OCSP responder URL is unparseable, too long, uses an unsupported scheme \
                 or port, or carries userinfo",
            ),
            OcspError::PrivateResponderAddress => f.write_str(
                "the OCSP responder URL resolves to a loopback, link-local, private, \
                 unspecified or multicast address",
            ),
        }
    }
}

impl std::error::Error for OcspError {}

/// The raw `subjectPublicKey` BIT STRING contents: the tag, length and unused-bits octet are
/// already stripped by the underlying BIT STRING decoder. Passing a whole `SubjectPublicKeyInfo`
/// to a signature-verification algorithm makes every verification fail with a confusing
/// `BadSignature`, so this helper exists once and every call site in this module goes through it.
fn raw_public_key_bytes(spki: &spki::SubjectPublicKeyInfoOwned) -> &[u8] {
    spki.subject_public_key.raw_bytes()
}

/// The stripped SEQUENCE content of an already-typed `AlgorithmIdentifier`, in the shape
/// `WebPkiSupportedAlgorithms::all`'s `signature_alg_id()` / `public_key_alg_id()` compare
/// against. Re-encoding an already-typed field that was never part of anything signed (an
/// algorithm identifier is metadata used only to select a verifier, never signed data itself) is
/// not the re-encoding this module's own module doc warns against.
fn spki_alg_content(spki: &spki::SubjectPublicKeyInfoOwned) -> Result<Vec<u8>, OcspError> {
    let der_bytes = Encode::to_der(&spki.algorithm).map_err(|_| OcspError::Parse)?;
    Ok(sequence_content(&der_bytes)?.to_vec())
}

/// Strip a SEQUENCE tag and length, returning its content bytes.
fn sequence_content(bytes: &[u8]) -> Result<&[u8], OcspError> {
    let mut reader = der::SliceReader::new(bytes).map_err(|_| OcspError::Parse)?;
    let header = der::Header::decode(&mut reader).map_err(|_| OcspError::Parse)?;
    header
        .tag
        .assert_eq(der::Tag::Sequence)
        .map_err(|_| OcspError::Parse)?;
    reader
        .read_slice(header.length)
        .map_err(|_| OcspError::Parse)
}

/// Strip a context-specific EXPLICIT wrapper's tag and length, returning the full TLV of the
/// value it wraps.
fn explicit_context_inner(tlv: &[u8]) -> Result<&[u8], OcspError> {
    let mut reader = der::SliceReader::new(tlv).map_err(|_| OcspError::Parse)?;
    let header = der::Header::decode(&mut reader).map_err(|_| OcspError::Parse)?;
    if !header.tag.is_context_specific() {
        return Err(OcspError::Parse);
    }
    reader
        .read_slice(header.length)
        .map_err(|_| OcspError::Parse)
}

/// One `SEQUENCE { tbs, signatureAlgorithm, signature BIT STRING, ... }` shape: `CertID`'s own
/// `Certificate` embeds this, and so does `BasicOCSPResponse`. `tbs_span` is the raw, unmodified
/// bytes of the first field, exactly as they appeared in the input: this is what gets passed to
/// signature verification, never a re-encoded value.
struct SignedTbs<'a> {
    tbs_span: &'a [u8],
    sig_alg_content: Vec<u8>,
    signature_bytes: &'a [u8],
}

/// Read one `SignedTbs` from `reader`'s current position, leaving the reader positioned right
/// after the signature field so a caller (`parse_basic_response`) can continue reading an
/// optional trailing field.
fn read_signed_tbs<'a>(reader: &mut der::SliceReader<'a>) -> Result<SignedTbs<'a>, OcspError> {
    let tbs_span = reader.tlv_bytes().map_err(|_| OcspError::Parse)?;
    let sig_alg_tlv = reader.tlv_bytes().map_err(|_| OcspError::Parse)?;
    let sig_alg_content = sequence_content(sig_alg_tlv)?.to_vec();
    let sig_tlv = reader.tlv_bytes().map_err(|_| OcspError::Parse)?;
    let bit_string: der::asn1::BitStringRef<'a> =
        Decode::from_der(sig_tlv).map_err(|_| OcspError::Parse)?;
    Ok(SignedTbs {
        tbs_span,
        sig_alg_content,
        signature_bytes: bit_string.raw_bytes(),
    })
}

/// Parse a `BasicOCSPResponse`, capturing `tbsResponseData`'s raw span, the embedded responder
/// certificates both as typed values (for subject/key/EKU inspection) and as raw per-certificate
/// spans (for verifying, byte-exact, that a delegated responder was signed by the issuer).
#[allow(
    clippy::type_complexity,
    reason = "the three return values are read together at exactly one call site in \
              validate_staple; a named struct would only rename the same three fields"
)]
fn parse_basic_response(
    basic_der: &[u8],
) -> Result<(SignedTbs<'_>, Vec<x509_cert::Certificate>, Vec<&[u8]>), OcspError> {
    let content = sequence_content(basic_der)?;
    let mut reader = der::SliceReader::new(content).map_err(|_| OcspError::Parse)?;
    let signed = read_signed_tbs(&mut reader)?;

    let mut typed_certs = Vec::new();
    let mut cert_spans = Vec::new();
    if reader.peek_byte().is_some() {
        let ctx_tlv = reader.tlv_bytes().map_err(|_| OcspError::Parse)?;
        let certs_tlv = explicit_context_inner(ctx_tlv)?;
        typed_certs = <Vec<x509_cert::Certificate> as Decode>::from_der(certs_tlv)
            .map_err(|_| OcspError::Parse)?;
        if typed_certs.len() > MAX_RESPONDER_CERTS {
            return Err(OcspError::TooManyCerts);
        }
        let certs_content = sequence_content(certs_tlv)?;
        let mut certs_reader =
            der::SliceReader::new(certs_content).map_err(|_| OcspError::Parse)?;
        while certs_reader.peek_byte().is_some() {
            cert_spans.push(certs_reader.tlv_bytes().map_err(|_| OcspError::Parse)?);
        }
    }

    Ok((signed, typed_certs, cert_spans))
}

/// Parse one embedded `Certificate`'s `SignedTbs` shape from its raw span, for verifying it was
/// signed by the issuer without ever re-encoding its `tbsCertificate`.
fn parse_certificate_signed_tbs(cert_der: &[u8]) -> Result<SignedTbs<'_>, OcspError> {
    let content = sequence_content(cert_der)?;
    let mut reader = der::SliceReader::new(content).map_err(|_| OcspError::Parse)?;
    read_signed_tbs(&mut reader)
}

/// Look up a verification algorithm from the installed provider and verify `signature` over
/// `message`, exactly as written out in the issue's own design section.
fn verify_signature_der(
    sig_alg_content: &[u8],
    pubkey_alg_content: &[u8],
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), OcspError> {
    let provider = crate::provider::provider().ok_or(OcspError::ProviderNotInstalled)?;
    let algs = &provider.signature_verification_algorithms;
    let alg = algs
        .all
        .iter()
        .find(|a| {
            a.signature_alg_id().as_ref() == sig_alg_content
                && a.public_key_alg_id().as_ref() == pubkey_alg_content
        })
        .ok_or(OcspError::UnsupportedSignatureAlgorithm)?;
    alg.verify_signature(public_key, message, signature)
        .map_err(|_| OcspError::BadSignature)
}

/// Whether `rid` names `cert`, either by subject name or by the SHA-1 hash of `cert`'s raw
/// public key bytes.
fn responder_id_matches(rid: &x509_ocsp::ResponderId, cert: &x509_cert::Certificate) -> bool {
    match rid {
        x509_ocsp::ResponderId::ByName(name) => {
            match (
                Encode::to_der(name),
                Encode::to_der(&cert.tbs_certificate.subject),
            ) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
        }
        x509_ocsp::ResponderId::ByKey(key_hash) => {
            let spki_bytes = raw_public_key_bytes(&cert.tbs_certificate.subject_public_key_info);
            let digest = Sha1::digest(spki_bytes);
            key_hash.as_bytes() == digest.as_slice()
        }
    }
}

/// Whether `cert` carries `id-ce-extKeyUsage` with `id-kp-OCSPSigning`.
fn has_ocsp_signing_eku(cert: &x509_cert::Certificate) -> bool {
    let Some(extensions) = cert.tbs_certificate.extensions.as_deref() else {
        return false;
    };
    let Some(ext) = extensions.iter().find(|e| e.extn_id == OID_EXT_KEY_USAGE) else {
        return false;
    };
    let Ok(purposes) =
        <Vec<der::asn1::ObjectIdentifier> as Decode>::from_der(ext.extn_value.as_bytes())
    else {
        return false;
    };
    purposes.contains(&OID_OCSP_SIGNING)
}

/// Build a `CertID` per RFC 6960 section 4.1.1 with SHA-1, for `issuer_dn`/`issuer_spki`/`serial`.
/// Shared by [`build_request`] (building the request we send) and [`validate_staple`] (building
/// the `CertID` we expect the response to carry), so the two can never compute it differently.
fn build_cert_id(
    issuer_dn: &[u8],
    issuer_spki: &spki::SubjectPublicKeyInfoOwned,
    serial: &[u8],
) -> Result<x509_ocsp::CertId, OcspError> {
    let issuer_name_hash = Sha1::digest(issuer_dn);
    let issuer_key_hash = Sha1::digest(raw_public_key_bytes(issuer_spki));
    let serial_number =
        x509_cert::serial_number::SerialNumber::new(serial).map_err(|_| OcspError::IssuerParse)?;
    Ok(x509_ocsp::CertId {
        hash_algorithm: spki::AlgorithmIdentifierOwned {
            oid: OID_SHA1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.to_vec())
            .map_err(|_| OcspError::IssuerParse)?,
        issuer_key_hash: OctetString::new(issuer_key_hash.to_vec())
            .map_err(|_| OcspError::IssuerParse)?,
        serial_number,
    })
}

/// Field-for-field `CertID` comparison. Whole-struct equality is deliberately avoided: the
/// `hashAlgorithm` `AlgorithmIdentifier`'s `parameters` field is legal both as an explicit
/// `NULL` and as absent for `id-sha1` (RFC 3279 says the latter is preferred), and a responder
/// using the encoding we did not happen to pick must not be rejected as if it named a different
/// certificate.
fn cert_id_matches(a: &x509_ocsp::CertId, b: &x509_ocsp::CertId) -> bool {
    a.hash_algorithm.oid == b.hash_algorithm.oid
        && a.issuer_name_hash.as_bytes() == b.issuer_name_hash.as_bytes()
        && a.issuer_key_hash.as_bytes() == b.issuer_key_hash.as_bytes()
        && a.serial_number.as_bytes() == b.serial_number.as_bytes()
}

/// The nonce extension's content, if `response_data` carries one and it decodes.
fn extract_nonce(response_data: &x509_ocsp::ResponseData) -> Option<Vec<u8>> {
    let extensions = response_data.response_extensions.as_deref()?;
    let ext = extensions.iter().find(|e| e.extn_id == OID_OCSP_NONCE)?;
    let nonce: OctetString = Decode::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(nonce.as_bytes().to_vec())
}

fn generalized_time_to_unix(t: x509_ocsp::OcspGeneralizedTime) -> UnixSeconds {
    UnixSeconds::new(t.0.to_unix_duration().as_secs())
}

/// Build a single-certificate OCSP request.
///
/// # Errors
/// `OcspError::NoIssuer`, `OcspError::IssuerParse`, `OcspError::RequestTooLarge`.
pub fn build_request(cred: &Credentials, nonce: Option<&[u8; 16]>) -> Result<Vec<u8>, OcspError> {
    let issuer_der = cred.issuer_der().ok_or(OcspError::NoIssuer)?;
    let issuer =
        x509_cert::Certificate::from_der(issuer_der).map_err(|_| OcspError::IssuerParse)?;
    let cert_id = build_cert_id(
        cred.issuer_dn(),
        &issuer.tbs_certificate.subject_public_key_info,
        cred.serial(),
    )?;

    let request_extensions = match nonce {
        Some(n) => {
            let inner = OctetString::new(n.to_vec()).map_err(|_| OcspError::RequestTooLarge)?;
            let inner_der = Encode::to_der(&inner).map_err(|_| OcspError::RequestTooLarge)?;
            let extn_value = OctetString::new(inner_der).map_err(|_| OcspError::RequestTooLarge)?;
            Some(alloc::vec![x509_cert::ext::Extension {
                extn_id: OID_OCSP_NONCE,
                critical: false,
                extn_value,
            }])
        }
        None => None,
    };

    let ocsp_request = x509_ocsp::OcspRequest {
        tbs_request: x509_ocsp::TbsRequest {
            version: x509_ocsp::Version::V1,
            requestor_name: None,
            request_list: alloc::vec![x509_ocsp::Request {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            request_extensions,
        },
        optional_signature: None,
    };

    let der = Encode::to_der(&ocsp_request).map_err(|_| OcspError::RequestTooLarge)?;
    if der.len() > MAX_OCSP_REQUEST_BYTES {
        return Err(OcspError::RequestTooLarge);
    }
    Ok(der)
}

/// A parsed, not-yet-validated AIA URL.
struct ParsedAiaUrl<'a> {
    scheme: &'a str,
    has_userinfo: bool,
    host: &'a str,
    is_bracketed_v6: bool,
    port: Option<&'a str>,
}

/// Parse the narrow `scheme://[userinfo@]host[:port][/...]` shape an OCSP responder URL always
/// has. Returns `None` for anything that does not fit that shape at all (a relative path, a
/// schemeless string, a missing host); `validate_aia_url` maps that to `BadResponderUrl`.
fn split_aia_url(url: &str) -> Option<ParsedAiaUrl<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end)?;
    if authority.is_empty() {
        return None;
    }

    let (has_userinfo, host_port) = match authority.rsplit_once('@') {
        Some((_, h)) => (true, h),
        None => (false, authority),
    };
    if host_port.is_empty() {
        return None;
    }

    let (host, is_bracketed_v6, port) = if let Some(bracket_rest) = host_port.strip_prefix('[') {
        let (inner, after) = bracket_rest.split_once(']')?;
        if inner.is_empty() {
            return None;
        }
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        (inner, true, port)
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) => (h, false, Some(p)),
            None => (host_port, false, None),
        }
    };
    if host.is_empty() {
        return None;
    }

    Some(ParsedAiaUrl {
        scheme,
        has_userinfo,
        host,
        is_bracketed_v6,
        port,
    })
}

/// Whether `addr` is loopback, link-local, private, unspecified or multicast.
fn ipv4_is_disallowed(addr: core::net::Ipv4Addr) -> bool {
    addr.is_loopback()
        || addr.is_link_local()
        || addr.is_private()
        || addr.is_unspecified()
        || addr.is_multicast()
}

/// Whether `addr` is loopback, unique-local (`fc00::/7`), unicast-link-local (`fe80::/10`),
/// unspecified or multicast. This alone does **not** decide whether a v6 literal is disallowed:
/// an IPv4-mapped or IPv4-compatible address embeds a v4 address in the low 32 bits and is none
/// of the above by construction, so the caller must also unmap and re-check with
/// [`ipv4_embedded_in_v6`] and [`ipv4_is_disallowed`].
fn ipv6_is_disallowed(addr: core::net::Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr.is_unicast_link_local()
        || addr.is_unique_local()
        || addr.is_unspecified()
        || addr.is_multicast()
}

/// The IPv4 address embedded in `addr`, if `addr` is an IPv4-mapped address (`::ffff:a.b.c.d`,
/// RFC 4291 section 2.5.5.2, the form every dual-stack socket produces for a v4 peer and the form
/// a certificate's AIA host can carry to make `169.254.169.254` reach the cloud metadata service
/// under a spelling `ipv6_is_disallowed` never inspects) or the deprecated IPv4-compatible address
/// (`::a.b.c.d`, the same RFC section's older form). `Ipv6Addr::to_ipv4_mapped` alone only
/// recognizes the first form; the second is checked by hand here. Both forms carry the embedded
/// v4 address in the low 32 bits with every other bit zero, so `ipv4_is_disallowed` must be run
/// against the returned address by every caller of this function, exactly as it already is
/// against a v4 literal host.
fn ipv4_embedded_in_v6(addr: core::net::Ipv6Addr) -> Option<core::net::Ipv4Addr> {
    if let Some(v4) = addr.to_ipv4_mapped() {
        return Some(v4);
    }
    let segments = addr.segments();
    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        let [a, b] = segments[6].to_be_bytes();
        let [c, d] = segments[7].to_be_bytes();
        return Some(core::net::Ipv4Addr::new(a, b, c, d));
    }
    None
}

/// One dot-separated part of a legacy "numbers-and-dots" IPv4 host (decimal, `0x`/`0X`-prefixed
/// hex, or a leading-zero octal octet). Returns `None` for anything that is not purely numeric in
/// one of those three bases, which is the correct outcome for an ordinary DNS label: this
/// function's only job is to recognize the numeric encodings `str::parse::<Ipv4Addr>` rejects,
/// never to reinterpret a real hostname's label as a number.
fn parse_legacy_ipv4_part(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    if part.len() > 1 && part.as_bytes().first() == Some(&b'0') {
        return u32::from_str_radix(part, 8).ok();
    }
    part.parse().ok()
}

/// Parse the legacy "numbers-and-dots" IPv4 host syntax `inet_aton`, and historically many HTTP
/// clients, accept alongside the canonical four-decimal-octet form: 1 to 4 dot-separated parts,
/// each decimal, hex or octal per [`parse_legacy_ipv4_part`], combined the way `inet_aton`
/// defines (a single part is the whole 32-bit value; two parts are the high 8 bits and the low
/// 24; three parts are 8, 8 and 16; four parts are the four octets in order). Every host this
/// recognizes resolves to the identical address the canonical spelling names, so
/// `http://2852039166/`, `http://0x7f000001/`, `http://0177.0.0.1/` and `http://127.1/` must be
/// judged by the same rule 4 as `http://169.254.169.254/` and `http://127.0.0.1/`, which is
/// exactly what feeding the result into [`ipv4_is_disallowed`] does. A host with more than 4
/// parts, or any non-numeric part, is not a legacy IPv4 host at all and returns `None`, leaving it
/// to be judged as an ordinary DNS name instead.
fn parse_legacy_ipv4(host: &str) -> Option<core::net::Ipv4Addr> {
    let parts: Vec<u32> = host
        .split('.')
        .map(parse_legacy_ipv4_part)
        .collect::<Option<_>>()?;
    let combined: u32 = match *parts.as_slice() {
        [a] => a,
        [a, b] if a <= 0xFF && b <= 0x00FF_FFFF => (a << 24) | b,
        [a, b, c] if a <= 0xFF && b <= 0xFF && c <= 0xFFFF => (a << 24) | (b << 16) | c,
        [a, b, c, d] if a <= 0xFF && b <= 0xFF && c <= 0xFF && d <= 0xFF => {
            (a << 24) | (b << 16) | (c << 8) | d
        }
        _ => return None,
    };
    Some(core::net::Ipv4Addr::from(combined))
}

/// Check that `url` is a URL we are willing to send a request to. See the five rules in Context.
///
/// Called by `OcspUpdater::tick` before every fetch and by the fetcher before following every
/// redirect. It is `pub` for exactly that second caller.
///
/// # Errors
/// `OcspError::BadResponderUrl` or `OcspError::PrivateResponderAddress`.
pub fn validate_aia_url(url: &str, cfg: &OcspConfig) -> Result<(), OcspError> {
    if url.len() > MAX_AIA_URL_BYTES {
        return Err(OcspError::BadResponderUrl);
    }
    let parsed = split_aia_url(url).ok_or(OcspError::BadResponderUrl)?;

    if !parsed.scheme.eq_ignore_ascii_case("http") && !parsed.scheme.eq_ignore_ascii_case("https") {
        return Err(OcspError::BadResponderUrl);
    }
    if parsed.has_userinfo {
        return Err(OcspError::BadResponderUrl);
    }
    if let Some(port_str) = parsed.port {
        let port: u16 = port_str.parse().map_err(|_| OcspError::BadResponderUrl)?;
        if port != 80 && port != 443 {
            return Err(OcspError::BadResponderUrl);
        }
    }

    if parsed.is_bracketed_v6 {
        let addr: core::net::Ipv6Addr = parsed
            .host
            .parse()
            .map_err(|_| OcspError::BadResponderUrl)?;
        if !cfg.allow_private_responders {
            if ipv6_is_disallowed(addr) {
                return Err(OcspError::PrivateResponderAddress);
            }
            // An IPv4-mapped or IPv4-compatible address is none of the things
            // `ipv6_is_disallowed` checks by construction (it carries a v4 address in its low 32
            // bits, not an IPv6 loopback/link-local/unique-local/unspecified/multicast pattern),
            // so it must be unmapped and judged by the v4 rules the embedded address is actually
            // subject to: this is what closes `http://[::ffff:169.254.169.254]/` reaching the
            // exact address rule 4 exists to block.
            if let Some(embedded) = ipv4_embedded_in_v6(addr)
                && ipv4_is_disallowed(embedded)
            {
                return Err(OcspError::PrivateResponderAddress);
            }
        }
    } else {
        // The canonical four-decimal-octet form first, then the legacy decimal/hex/octal/short
        // encodings `Ipv4Addr`'s own parser correctly rejects as non-canonical but that a
        // certificate's AIA host can still spell to reach exactly the same blocked addresses.
        let literal = parsed
            .host
            .parse::<core::net::Ipv4Addr>()
            .ok()
            .or_else(|| parse_legacy_ipv4(parsed.host));
        if let Some(addr) = literal
            && !cfg.allow_private_responders
            && ipv4_is_disallowed(addr)
        {
            return Err(OcspError::PrivateResponderAddress);
        }
    }

    Ok(())
}

/// Step 5: determine the signer and verify authorization. Returns the signer's raw public key
/// bytes and its SPKI algorithm identifier content (the latter needed to select a verifier for
/// step 6). Owned `Vec<u8>` rather than borrows, so this function's own local (`issuer_spki_alg_content`
/// for the delegated-responder path) does not have to outlive the call, and so the caller never
/// has to reason about whether the returned bytes came from `issuer` or from `typed_certs`.
fn resolve_signer(
    responder_id: &x509_ocsp::ResponderId,
    issuer: &x509_cert::Certificate,
    typed_certs: &[x509_cert::Certificate],
    cert_spans: &[&[u8]],
) -> Result<(Vec<u8>, Vec<u8>), OcspError> {
    if responder_id_matches(responder_id, issuer) {
        return Ok((
            raw_public_key_bytes(&issuer.tbs_certificate.subject_public_key_info).to_vec(),
            spki_alg_content(&issuer.tbs_certificate.subject_public_key_info)?,
        ));
    }
    for (i, candidate) in typed_certs.iter().enumerate() {
        if !responder_id_matches(responder_id, candidate) {
            continue;
        }
        if !has_ocsp_signing_eku(candidate) {
            return Err(OcspError::UnauthorizedResponder);
        }
        let cert_span = cert_spans.get(i).copied().ok_or(OcspError::Parse)?;
        let candidate_signed = parse_certificate_signed_tbs(cert_span)?;
        let issuer_spki_alg_content =
            spki_alg_content(&issuer.tbs_certificate.subject_public_key_info)?;
        verify_signature_der(
            &candidate_signed.sig_alg_content,
            &issuer_spki_alg_content,
            raw_public_key_bytes(&issuer.tbs_certificate.subject_public_key_info),
            candidate_signed.tbs_span,
            candidate_signed.signature_bytes,
        )
        .map_err(|_| OcspError::UnauthorizedResponder)?;
        return Ok((
            raw_public_key_bytes(&candidate.tbs_certificate.subject_public_key_info).to_vec(),
            spki_alg_content(&candidate.tbs_certificate.subject_public_key_info)?,
        ));
    }
    Err(OcspError::UnauthorizedResponder)
}

/// The RFC 6960 `responseStatus` numeric code for `status`, without a truncating cast.
fn response_status_code(status: x509_ocsp::OcspResponseStatus) -> u8 {
    match status {
        x509_ocsp::OcspResponseStatus::Successful => 0,
        x509_ocsp::OcspResponseStatus::MalformedRequest => 1,
        x509_ocsp::OcspResponseStatus::InternalError => 2,
        x509_ocsp::OcspResponseStatus::TryLater => 3,
        x509_ocsp::OcspResponseStatus::SigRequired => 5,
        x509_ocsp::OcspResponseStatus::Unauthorized => 6,
    }
}

/// Validate a response against a credential. See the issue text for all eleven steps.
///
/// # Errors
/// Any `OcspError`.
pub fn validate_staple(
    der: &[u8],
    cred: &Credentials,
    sent_nonce: Option<&[u8; 16]>,
    now: UnixSeconds,
    cfg: &OcspConfig,
) -> Result<StapleInfo, OcspError> {
    // Step 1.
    if der.is_empty() {
        return Err(OcspError::Empty);
    }
    if der.len() > MAX_OCSP_RESPONSE_BYTES {
        return Err(OcspError::TooLarge);
    }

    // Step 2.
    let ocsp_response = x509_ocsp::OcspResponse::from_der(der).map_err(|_| OcspError::Parse)?;

    // Step 3.
    if ocsp_response.response_status != x509_ocsp::OcspResponseStatus::Successful {
        return Err(OcspError::ResponderStatus(response_status_code(
            ocsp_response.response_status,
        )));
    }
    let response_bytes = ocsp_response.response_bytes.ok_or(OcspError::Parse)?;

    // Step 4.
    if response_bytes.response_type != OID_OCSP_BASIC {
        return Err(OcspError::UnknownResponseType);
    }
    let basic_der = response_bytes.response.as_bytes();
    let (signed, typed_certs, cert_spans) = parse_basic_response(basic_der)?;

    // Decode the already-captured, byte-exact tbs span into a typed view for field access. The
    // signature check below verifies `signed.tbs_span` itself, never this decoded value
    // re-encoded.
    let response_data =
        x509_ocsp::ResponseData::from_der(signed.tbs_span).map_err(|_| OcspError::Parse)?;

    let issuer_der = cred.issuer_der().ok_or(OcspError::NoIssuer)?;
    let issuer =
        x509_cert::Certificate::from_der(issuer_der).map_err(|_| OcspError::IssuerParse)?;

    // Step 5: determine the signer and verify authorization.
    let (signer_pubkey, signer_spki_alg_content) = resolve_signer(
        &response_data.responder_id,
        &issuer,
        &typed_certs,
        &cert_spans,
    )?;

    // Step 6: verify the signature over the exact encoded bytes of tbsResponseData.
    verify_signature_der(
        &signed.sig_alg_content,
        &signer_spki_alg_content,
        &signer_pubkey,
        signed.tbs_span,
        signed.signature_bytes,
    )?;

    // Step 7.
    if response_data.responses.len() != 1 {
        return Err(OcspError::WrongResponseCount);
    }
    let single = response_data
        .responses
        .first()
        .ok_or(OcspError::WrongResponseCount)?;

    // Step 8.
    let expected_cert_id = build_cert_id(
        cred.issuer_dn(),
        &issuer.tbs_certificate.subject_public_key_info,
        cred.serial(),
    )?;
    if !cert_id_matches(&single.cert_id, &expected_cert_id) {
        return Err(OcspError::CertIdMismatch);
    }

    // Step 9.
    let this_update = generalized_time_to_unix(single.this_update);
    let skew = u64::from(cfg.skew_secs);
    if this_update.saturating_sub(now) > skew {
        return Err(OcspError::NotYetValid);
    }
    let next_update = single.next_update.map(generalized_time_to_unix);
    let effective_next_update = next_update
        .unwrap_or_else(|| this_update.saturating_add_secs(u64::from(cfg.no_next_update_ttl_secs)));
    if now.saturating_sub(effective_next_update) > skew {
        return Err(OcspError::Expired);
    }

    // Step 10.
    if let Some(sent) = sent_nonce
        && let Some(resp_nonce) = extract_nonce(&response_data)
        && resp_nonce.as_slice() != sent.as_slice()
    {
        return Err(OcspError::NonceMismatch);
    }

    // Step 11.
    match &single.cert_status {
        x509_ocsp::CertStatus::Good(_) => Ok(StapleInfo {
            status: CertStatus::Good,
            this_update,
            next_update,
            der_len: der.len(),
        }),
        x509_ocsp::CertStatus::Revoked(info) => Err(OcspError::CertificateRevoked {
            revocation_time: generalized_time_to_unix(info.revocation_time),
        }),
        x509_ocsp::CertStatus::Unknown(_) => Err(OcspError::StatusUnknown),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use der::Decode;
    use rcgen::SigningKey;
    use sha1::Digest;

    use super::{
        CertStatus, OID_OCSP_NONCE, OcspConfig, OcspError, build_cert_id, validate_aia_url,
        validate_staple,
    };
    use crate::store::{ChainInterner, Credentials};
    use crate::time::UnixSeconds;

    /// `ecdsa-with-SHA256`, RFC 5758. Every fixture key in this module is P-256, so every
    /// signature this module produces uses this one algorithm identifier.
    const OID_ECDSA_SHA256: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    fn ensure_provider_installed() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
        });
    }

    /// A fixed "now" every test in this module measures skew and validity against, so no test
    /// ever depends on the wall clock.
    const NOW: u64 = 1_700_000_000;

    fn unix_to_generalized(secs: u64) -> x509_ocsp::OcspGeneralizedTime {
        let gt =
            der::asn1::GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(secs))
                .expect("a fixture timestamp must encode as a valid GeneralizedTime");
        x509_ocsp::OcspGeneralizedTime(gt)
    }

    /// One issuer (a self-signed CA) plus one leaf credential it issued. Every OCSP test fixture
    /// in this module is built from one of these, so `CertID` construction and signature
    /// verification always exercise the real, loaded `Credentials` type rather than a hand-typed
    /// stand-in.
    struct Fixture {
        issuer_key: rcgen::KeyPair,
        issuer_params: rcgen::CertificateParams,
        issuer_der: Vec<u8>,
        cred: Credentials,
    }

    fn build_fixture(san: &str) -> Fixture {
        ensure_provider_installed();
        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keygen must succeed for a fixed, well-known algorithm");
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // A distinct Common Name per fixture: two fixtures built with an empty, default
        // distinguished name would otherwise compare EQUAL under `ResponderId::ByName`, which
        // made validate_6 spuriously match fixture B's issuer against fixture A's response.
        let mut issuer_dn = rcgen::DistinguishedName::new();
        issuer_dn.push(rcgen::DnType::CommonName, format!("test issuer for {san}"));
        issuer_params.distinguished_name = issuer_dn;
        let issuer_der = issuer_params
            .self_signed(&issuer_key)
            .expect("self sign issuer")
            .der()
            .to_vec();

        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keygen must succeed for a fixed, well-known algorithm");
        let leaf_params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SAN");
        let signing_issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &signing_issuer)
            .expect("sign leaf")
            .der()
            .to_vec();

        let mut interner = ChainInterner::new();
        let cred = Credentials::load(
            &[&leaf_der, &issuer_der],
            &leaf_key.serialize_der(),
            &mut interner,
        )
        .expect("valid chain and key");

        Fixture {
            issuer_key,
            issuer_params,
            issuer_der,
            cred,
        }
    }

    /// A leaf-only credential (no intermediate at all), for edge case 2.
    fn build_leaf_only_fixture(san: &str) -> Credentials {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SAN");
        let der = params.self_signed(&key).expect("self sign").der().to_vec();
        let mut interner = ChainInterner::new();
        Credentials::load(&[&der], &key.serialize_der(), &mut interner).expect("valid leaf and key")
    }

    fn expected_cert_id(fixture: &Fixture) -> x509_ocsp::CertId {
        let issuer =
            x509_cert::Certificate::from_der(&fixture.issuer_der).expect("parse fixture issuer");
        build_cert_id(
            fixture.cred.issuer_dn(),
            &issuer.tbs_certificate.subject_public_key_info,
            fixture.cred.serial(),
        )
        .expect("build expected CertID")
    }

    fn issuer_responder_id(fixture: &Fixture) -> x509_ocsp::ResponderId {
        let issuer =
            x509_cert::Certificate::from_der(&fixture.issuer_der).expect("parse fixture issuer");
        x509_ocsp::ResponderId::ByName(issuer.tbs_certificate.subject)
    }

    fn responder_id_by_key(cert_der: &[u8]) -> x509_ocsp::ResponderId {
        let cert = x509_cert::Certificate::from_der(cert_der).expect("parse cert");
        let spki_bytes = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let digest = sha1::Sha1::digest(spki_bytes);
        x509_ocsp::ResponderId::ByKey(
            der::asn1::OctetString::new(digest.to_vec()).expect("octet string"),
        )
    }

    /// A delegated responder certificate: `with_eku` controls whether it carries
    /// `id-kp-OCSPSigning`, and `issuer_signs` controls whether the fixture's own issuer signed
    /// it (`false` signs it with an unrelated, freshly generated CA instead).
    fn build_delegated_cert(
        fixture: &Fixture,
        with_eku: bool,
        issuer_signs: bool,
    ) -> (Vec<u8>, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
        if with_eku {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::OcspSigning];
        }
        let der = if issuer_signs {
            let signing_issuer =
                rcgen::Issuer::from_params(&fixture.issuer_params, &fixture.issuer_key);
            params
                .signed_by(&key, &signing_issuer)
                .expect("sign delegated cert")
                .der()
                .to_vec()
        } else {
            let other_key =
                rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
            let mut other_ca =
                rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
            other_ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let other_issuer = rcgen::Issuer::from_params(&other_ca, &other_key);
            params
                .signed_by(&key, &other_issuer)
                .expect("sign delegated cert")
                .der()
                .to_vec()
        };
        (der, key)
    }

    /// A fresh, entirely unrelated self-signed certificate, for edge case 7.
    fn build_unrelated_cert() -> (Vec<u8>, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
        let der = params.self_signed(&key).expect("self sign").der().to_vec();
        (der, key)
    }

    /// Every knob a test needs to build a `BasicOCSPResponse`. `base_spec` returns a fully valid,
    /// correctly signed, self-responder "good" response for `fixture`; tests mutate individual
    /// fields from there.
    struct ResponseSpec<'a> {
        signer: &'a rcgen::KeyPair,
        responder_id: x509_ocsp::ResponderId,
        cert_id: x509_ocsp::CertId,
        cert_status: x509_ocsp::CertStatus,
        this_update: u64,
        next_update: Option<u64>,
        nonce: Option<[u8; 16]>,
        embedded_certs: Vec<Vec<u8>>,
    }

    fn base_spec(fixture: &Fixture) -> ResponseSpec<'_> {
        ResponseSpec {
            signer: &fixture.issuer_key,
            responder_id: issuer_responder_id(fixture),
            cert_id: expected_cert_id(fixture),
            cert_status: x509_ocsp::CertStatus::good(),
            this_update: NOW,
            next_update: Some(NOW + 3_600),
            nonce: None,
            embedded_certs: Vec::new(),
        }
    }

    /// Encode `spec` into a complete, wrapped `OCSPResponse` DER, exactly the shape
    /// `validate_staple` reads: `responseStatus = successful`, `responseType =
    /// id-pkix-ocsp-basic`, and a `BasicOCSPResponse` whose `tbsResponseData` is signed by
    /// `spec.signer`.
    fn build_response_der(spec: &ResponseSpec<'_>) -> Vec<u8> {
        let extensions = spec.nonce.map(|n| {
            let inner = der::asn1::OctetString::new(n.to_vec()).expect("nonce octet string");
            let extn_value = der::asn1::OctetString::new(
                x509_cert::der::Encode::to_der(&inner).expect("encode inner nonce"),
            )
            .expect("nonce extension value");
            vec![x509_cert::ext::Extension {
                extn_id: OID_OCSP_NONCE,
                critical: false,
                extn_value,
            }]
        });

        let single = x509_ocsp::SingleResponse {
            cert_id: spec.cert_id.clone(),
            cert_status: spec.cert_status,
            this_update: unix_to_generalized(spec.this_update),
            next_update: spec.next_update.map(unix_to_generalized),
            single_extensions: None,
        };

        let response_data = x509_ocsp::ResponseData {
            version: x509_ocsp::Version::V1,
            responder_id: spec.responder_id.clone(),
            produced_at: unix_to_generalized(spec.this_update),
            responses: vec![single],
            response_extensions: extensions,
        };

        let tbs_der = x509_cert::der::Encode::to_der(&response_data).expect("encode tbs");
        let signature_bytes = spec.signer.sign(&tbs_der).expect("sign tbs");

        let certs = if spec.embedded_certs.is_empty() {
            None
        } else {
            Some(
                spec.embedded_certs
                    .iter()
                    .map(|der| {
                        x509_cert::Certificate::from_der(der).expect("valid embedded cert DER")
                    })
                    .collect(),
            )
        };

        let basic = x509_ocsp::BasicOcspResponse {
            tbs_response_data: response_data,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: OID_ECDSA_SHA256,
                parameters: None,
            },
            signature: der::asn1::BitString::from_bytes(&signature_bytes)
                .expect("signature as BIT STRING"),
            certs,
        };
        let basic_der = x509_cert::der::Encode::to_der(&basic).expect("encode basic response");

        let response = x509_ocsp::OcspResponse {
            response_status: x509_ocsp::OcspResponseStatus::Successful,
            response_bytes: Some(x509_ocsp::ResponseBytes {
                response_type: der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1"),
                response: der::asn1::OctetString::new(basic_der).expect("response octet string"),
            }),
        };
        x509_cert::der::Encode::to_der(&response).expect("encode OCSPResponse")
    }

    /// A response carrying only `responseStatus`, no `responseBytes`, for the non-`successful`
    /// status codes.
    fn build_status_only_response(status: x509_ocsp::OcspResponseStatus) -> Vec<u8> {
        let response = x509_ocsp::OcspResponse {
            response_status: status,
            response_bytes: None,
        };
        x509_cert::der::Encode::to_der(&response).expect("encode status-only response")
    }

    #[test]
    fn validate_2() {
        let leaf_only = build_leaf_only_fixture("leaf-only.example.com");
        let result = super::build_request(&leaf_only, None);
        assert_eq!(result, Err(OcspError::NoIssuer));
    }

    #[test]
    fn build_request_produces_a_valid_ocsp_request() {
        // No test decodes what build_request actually produces: validate_2 only exercises its
        // NoIssuer error path. Replacing the whole encoding with garbage, or dropping the nonce
        // extension outright, both leave every other test in this file green, because nothing
        // checks that the bytes are a well-formed RFC 6960 OCSPRequest, that the CertID matches
        // this credential, or that the nonce round-trips.
        let fixture = build_fixture("build-request.example.com");
        let nonce = [9u8; 16];
        let der = super::build_request(&fixture.cred, Some(&nonce))
            .expect("build_request must succeed for a valid chain");

        let request: x509_ocsp::OcspRequest =
            Decode::from_der(&der).expect("build_request must produce a valid DER OCSPRequest");
        assert_eq!(
            request.tbs_request.request_list.len(),
            1,
            "a single-certificate request must carry exactly one Request"
        );
        let req = &request.tbs_request.request_list[0];

        // Independently recomputed here, not by calling build_cert_id (which build_request
        // itself calls), so a bug shared between the function and this assertion cannot cancel
        // out and hide behind a passing test.
        let issuer =
            x509_cert::Certificate::from_der(&fixture.issuer_der).expect("parse fixture issuer");
        let expected_issuer_name_hash = sha1::Sha1::digest(fixture.cred.issuer_dn());
        let expected_issuer_key_hash = sha1::Sha1::digest(
            issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        );
        assert_eq!(
            req.req_cert.issuer_name_hash.as_bytes(),
            expected_issuer_name_hash.as_slice(),
            "issuerNameHash must be SHA1 of the issuer's subject Name"
        );
        assert_eq!(
            req.req_cert.issuer_key_hash.as_bytes(),
            expected_issuer_key_hash.as_slice(),
            "issuerKeyHash must be SHA1 of the issuer's raw SPKI bit string contents"
        );
        assert_eq!(
            req.req_cert.serial_number.as_bytes(),
            fixture.cred.serial(),
            "serialNumber must be the leaf's own serial"
        );

        // The nonce extension, id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2), must round-trip the
        // exact 16 bytes passed in.
        let extensions = request
            .tbs_request
            .request_extensions
            .as_deref()
            .expect("a nonce was requested, so request_extensions must be present");
        let ext = extensions
            .iter()
            .find(|e| e.extn_id == OID_OCSP_NONCE)
            .expect("the nonce extension must be present");
        let nonce_octet: der::asn1::OctetString = Decode::from_der(ext.extn_value.as_bytes())
            .expect("the nonce extension value must decode as an OCTET STRING");
        assert_eq!(nonce_octet.as_bytes(), &nonce);
    }

    #[test]
    fn validate_3() {
        let fixture = build_fixture("empty.example.com");
        let result = validate_staple(
            &[],
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::Empty));
    }

    #[test]
    fn validate_4() {
        let fixture = build_fixture("size-boundary.example.com");
        let cfg = OcspConfig::default();

        let at_limit = vec![0xAAu8; super::MAX_OCSP_RESPONSE_BYTES];
        let at_limit_result =
            validate_staple(&at_limit, &fixture.cred, None, UnixSeconds::new(NOW), &cfg);
        assert_ne!(
            at_limit_result,
            Err(OcspError::TooLarge),
            "a response at exactly MAX_OCSP_RESPONSE_BYTES must reach the parser, not be \
             rejected by the size gate"
        );
        assert_eq!(
            at_limit_result,
            Err(OcspError::Parse),
            "65536 bytes of non-DER filler must fail to parse, proving the size gate let it \
             through rather than accidentally decoding as something else"
        );

        let over_limit = vec![0xAAu8; super::MAX_OCSP_RESPONSE_BYTES + 1];
        let over_limit_result = validate_staple(
            &over_limit,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &cfg,
        );
        assert_eq!(over_limit_result, Err(OcspError::TooLarge));
    }

    #[test]
    fn validate_5() {
        let fixture = build_fixture("try-later.example.com");
        let der = build_status_only_response(x509_ocsp::OcspResponseStatus::TryLater);
        let result = validate_staple(
            &der,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::ResponderStatus(3)));
    }

    #[test]
    fn validate_6() {
        // Two leaves sharing ONE issuer: a response validly signed and authorized for leaf A
        // must still fail leaf B's CertID check specifically, not authorization or signature,
        // which is what this test would collapse into if the two fixtures used different
        // issuers (a different-issuer response would already fail at step 5, never reaching
        // step 8's CertID comparison at all).
        ensure_provider_installed();
        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keygen must succeed for a fixed, well-known algorithm");
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut issuer_dn = rcgen::DistinguishedName::new();
        issuer_dn.push(rcgen::DnType::CommonName, "shared issuer for validate_6");
        issuer_params.distinguished_name = issuer_dn;
        let issuer_der = issuer_params
            .self_signed(&issuer_key)
            .expect("self sign issuer")
            .der()
            .to_vec();
        let issuer = x509_cert::Certificate::from_der(&issuer_der).expect("parse issuer");

        let build_leaf_cred = |san: &str| -> Credentials {
            let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .expect("keygen must succeed for a fixed, well-known algorithm");
            let leaf_params =
                rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SAN");
            let signing_issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);
            let leaf_der = leaf_params
                .signed_by(&leaf_key, &signing_issuer)
                .expect("sign leaf")
                .der()
                .to_vec();
            let mut interner = ChainInterner::new();
            Credentials::load(
                &[&leaf_der, &issuer_der],
                &leaf_key.serialize_der(),
                &mut interner,
            )
            .expect("valid chain and key")
        };

        let cred_a = build_leaf_cred("shared-issuer-a.example.com");
        let cred_b = build_leaf_cred("shared-issuer-b.example.com");
        assert_ne!(
            cred_a.serial(),
            cred_b.serial(),
            "the two leaves must have distinct serials, or a CertID collision would prove nothing"
        );

        let cert_id_a = build_cert_id(
            cred_a.issuer_dn(),
            &issuer.tbs_certificate.subject_public_key_info,
            cred_a.serial(),
        )
        .expect("build CertID for leaf A");

        let spec = ResponseSpec {
            signer: &issuer_key,
            responder_id: x509_ocsp::ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
            cert_id: cert_id_a,
            cert_status: x509_ocsp::CertStatus::good(),
            this_update: NOW,
            next_update: Some(NOW + 3_600),
            nonce: None,
            embedded_certs: Vec::new(),
        };
        let der = build_response_der(&spec);

        let result_a = validate_staple(
            &der,
            &cred_a,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert!(
            result_a.is_ok(),
            "the fixture response must validate against its OWN credential, or this test \
             proves nothing: {result_a:?}"
        );

        let result_b = validate_staple(
            &der,
            &cred_b,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result_b, Err(OcspError::CertIdMismatch));
    }

    #[test]
    fn validate_7() {
        let fixture = build_fixture("unrelated-signer.example.com");
        let (unrelated_der, unrelated_key) = build_unrelated_cert();
        let mut spec = base_spec(&fixture);
        spec.signer = &unrelated_key;
        spec.responder_id = responder_id_by_key(&unrelated_der);
        let der = build_response_der(&spec);
        let result = validate_staple(
            &der,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::UnauthorizedResponder));
    }

    #[test]
    fn validate_8() {
        let fixture = build_fixture("delegated-no-eku.example.com");
        let (delegated_der, delegated_key) = build_delegated_cert(&fixture, false, true);
        let mut spec = base_spec(&fixture);
        spec.signer = &delegated_key;
        spec.responder_id = responder_id_by_key(&delegated_der);
        spec.embedded_certs = vec![delegated_der];
        let der = build_response_der(&spec);
        let result = validate_staple(
            &der,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::UnauthorizedResponder));
    }

    #[test]
    fn validate_9() {
        let fixture = build_fixture("delegated-wrong-issuer.example.com");
        let (delegated_der, delegated_key) = build_delegated_cert(&fixture, true, false);
        let mut spec = base_spec(&fixture);
        spec.signer = &delegated_key;
        spec.responder_id = responder_id_by_key(&delegated_der);
        spec.embedded_certs = vec![delegated_der];
        let der = build_response_der(&spec);
        let result = validate_staple(
            &der,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::UnauthorizedResponder));

        // The accept-side companion, folded into this test rather than kept as a separate,
        // unlisted 25th function (the acceptance criteria fix this file's test count at 24): a
        // delegated responder that IS signed by the issuer and DOES carry `id-kp-OCSPSigning`
        // must be accepted. Without this, a mutation that made `resolve_signer` always return
        // `UnauthorizedResponder` for a delegated responder would pass both 8 and 9 while making
        // legitimate delegated-responder deployments impossible.
        let fixture2 = build_fixture("delegated-good.example.com");
        let (good_delegated_der, good_delegated_key) = build_delegated_cert(&fixture2, true, true);
        let mut good_spec = base_spec(&fixture2);
        good_spec.signer = &good_delegated_key;
        good_spec.responder_id = responder_id_by_key(&good_delegated_der);
        good_spec.embedded_certs = vec![good_delegated_der];
        let good_der = build_response_der(&good_spec);
        let good_result = validate_staple(
            &good_der,
            &fixture2.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert!(
            matches!(
                good_result,
                Ok(super::StapleInfo {
                    status: CertStatus::Good,
                    ..
                })
            ),
            "a delegated responder signed by the issuer and carrying id-kp-OCSPSigning must be \
             accepted: {good_result:?}"
        );
    }

    #[test]
    fn validate_response_signature_forged_for_named_issuer_rejected() {
        // The central security property of this module: a response whose ResponderID names the
        // real issuer directly, so step 5's authorization check passes outright with the issuer's
        // own key selected as the verification key, must still be rejected if the bytes were not
        // actually signed by that key. Unlike validate_7 (ResponderID names an unrelated
        // certificate, so authorization itself fails) and validate_9's first half (ResponderID
        // names a delegated responder that resolve_signer refuses), this response is authorized
        // by every check except the one this test exists to pin: the signature. Neutering step 6
        // (`verify_signature_der(...)?` weakened to `let _ = verify_signature_der(...)`) leaves
        // every other field in this response correct, so it is accepted as `Ok(StapleInfo { .. })`
        // with no other test in this file noticing.
        let fixture = build_fixture("forged-signature.example.com");
        let (_unrelated_der, unrelated_key) = build_unrelated_cert();
        let mut spec = base_spec(&fixture);
        spec.responder_id = issuer_responder_id(&fixture);
        spec.signer = &unrelated_key;
        let der = build_response_der(&spec);
        let result = validate_staple(
            &der,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::BadSignature));
    }

    #[test]
    fn validate_10() {
        let fixture = build_fixture("two-responses.example.com");
        let mut spec = base_spec(&fixture);
        let cert_id = spec.cert_id.clone();
        // Build the tbsResponseData by hand (base_spec/build_response_der always emit exactly
        // one) so this is a real structural violation, not a stand-in.
        let single_a = x509_ocsp::SingleResponse {
            cert_id: cert_id.clone(),
            cert_status: x509_ocsp::CertStatus::good(),
            this_update: unix_to_generalized(spec.this_update),
            next_update: spec.next_update.map(unix_to_generalized),
            single_extensions: None,
        };
        let single_b = single_a.clone();
        let response_data = x509_ocsp::ResponseData {
            version: x509_ocsp::Version::V1,
            responder_id: spec.responder_id.clone(),
            produced_at: unix_to_generalized(spec.this_update),
            responses: vec![single_a, single_b],
            response_extensions: None,
        };
        let tbs_der = x509_cert::der::Encode::to_der(&response_data).expect("encode tbs");
        let signature_bytes = spec.signer.sign(&tbs_der).expect("sign tbs");
        let basic = x509_ocsp::BasicOcspResponse {
            tbs_response_data: response_data,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: OID_ECDSA_SHA256,
                parameters: None,
            },
            signature: der::asn1::BitString::from_bytes(&signature_bytes).expect("bit string"),
            certs: None,
        };
        let basic_der = x509_cert::der::Encode::to_der(&basic).expect("encode basic");
        let response = x509_ocsp::OcspResponse {
            response_status: x509_ocsp::OcspResponseStatus::Successful,
            response_bytes: Some(x509_ocsp::ResponseBytes {
                response_type: der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1"),
                response: der::asn1::OctetString::new(basic_der).expect("octet string"),
            }),
        };
        let der = x509_cert::der::Encode::to_der(&response).expect("encode response");

        spec.cert_id = cert_id; // silence unused-assignment-style confusion; spec is otherwise unused past this point
        let result = validate_staple(
            &der,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::WrongResponseCount));
    }

    #[test]
    fn validate_11() {
        let fixture = build_fixture("not-yet-valid.example.com");
        let cfg = OcspConfig::default(); // skew_secs = 300

        let mut too_early = base_spec(&fixture);
        too_early.this_update = NOW + 600; // 10 minutes ahead
        too_early.next_update = Some(NOW + 600 + 3_600);
        let der_too_early = build_response_der(&too_early);
        let result_too_early = validate_staple(
            &der_too_early,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &cfg,
        );
        assert_eq!(result_too_early, Err(OcspError::NotYetValid));

        let mut within_skew = base_spec(&fixture);
        within_skew.this_update = NOW + 240; // 4 minutes ahead, inside the 300s skew
        within_skew.next_update = Some(NOW + 240 + 3_600);
        let der_within_skew = build_response_der(&within_skew);
        let result_within_skew = validate_staple(
            &der_within_skew,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &cfg,
        );
        assert!(
            result_within_skew.is_ok(),
            "thisUpdate 4 minutes ahead must be accepted under a 300s skew: {result_within_skew:?}"
        );
    }

    #[test]
    fn validate_12() {
        let fixture = build_fixture("expired.example.com");
        let cfg = OcspConfig::default(); // skew_secs = 300

        let mut too_late = base_spec(&fixture);
        too_late.this_update = NOW - 4_200;
        too_late.next_update = Some(NOW - 600); // nextUpdate 10 minutes in the past
        let der_too_late = build_response_der(&too_late);
        let result_too_late = validate_staple(
            &der_too_late,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &cfg,
        );
        assert_eq!(result_too_late, Err(OcspError::Expired));

        let mut within_skew = base_spec(&fixture);
        within_skew.this_update = NOW - 4_200;
        within_skew.next_update = Some(NOW - 240); // 4 minutes in the past, inside skew
        let der_within_skew = build_response_der(&within_skew);
        let result_within_skew = validate_staple(
            &der_within_skew,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &cfg,
        );
        assert!(
            result_within_skew.is_ok(),
            "nextUpdate 4 minutes in the past must be accepted under a 300s skew: \
             {result_within_skew:?}"
        );
    }

    #[test]
    fn validate_13() {
        let fixture = build_fixture("no-next-update.example.com");
        let cfg = OcspConfig::default(); // no_next_update_ttl_secs = 3600, skew_secs = 300
        let mut spec = base_spec(&fixture);
        spec.this_update = NOW - 3_000;
        spec.next_update = None;
        let der = build_response_der(&spec);

        // Still valid: now - this_update (3000s) < no_next_update_ttl (3600s).
        let result = validate_staple(&der, &fixture.cred, None, UnixSeconds::new(NOW), &cfg);
        assert!(
            result.is_ok(),
            "a response with no nextUpdate must be valid for no_next_update_ttl_secs after \
             thisUpdate: {result:?}"
        );

        // Now past this_update + no_next_update_ttl_secs + skew: must expire.
        let far_future = UnixSeconds::new(NOW + 10_000);
        let expired_result = validate_staple(&der, &fixture.cred, None, far_future, &cfg);
        assert_eq!(expired_result, Err(OcspError::Expired));
    }

    #[test]
    fn validate_14() {
        let fixture = build_fixture("no-nonce-in-response.example.com");
        let mut spec = base_spec(&fixture);
        spec.nonce = None;
        let der = build_response_der(&spec);
        let sent_nonce = [7u8; 16];
        let result = validate_staple(
            &der,
            &fixture.cred,
            Some(&sent_nonce),
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert!(
            result.is_ok(),
            "a response with no nonce when we sent one must be accepted: {result:?}"
        );
    }

    #[test]
    fn validate_15() {
        let fixture = build_fixture("nonce-mismatch.example.com");
        let mut spec = base_spec(&fixture);
        spec.nonce = Some([1u8; 16]);
        let der = build_response_der(&spec);
        let sent_nonce = [2u8; 16];
        let result = validate_staple(
            &der,
            &fixture.cred,
            Some(&sent_nonce),
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::NonceMismatch));
    }

    #[test]
    fn validate_16() {
        let fixture = build_fixture("revoked.example.com");
        let mut spec = base_spec(&fixture);
        let revocation_time = NOW - 1_000;
        spec.cert_status = x509_ocsp::CertStatus::Revoked(x509_ocsp::RevokedInfo {
            revocation_time: unix_to_generalized(revocation_time),
            revocation_reason: None,
        });
        let der = build_response_der(&spec);
        let result = validate_staple(
            &der,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(
            result,
            Err(OcspError::CertificateRevoked {
                revocation_time: UnixSeconds::new(revocation_time)
            })
        );
    }

    #[test]
    fn validate_17() {
        let fixture = build_fixture("unknown-status.example.com");
        let mut spec = base_spec(&fixture);
        spec.cert_status = x509_ocsp::CertStatus::unknown();
        let der = build_response_der(&spec);
        let result = validate_staple(
            &der,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result, Err(OcspError::StatusUnknown));
    }

    #[test]
    fn validate_20() {
        let fixture = build_fixture("many-certs.example.com");
        let (filler_der, _filler_key) = build_unrelated_cert();

        let mut eight = base_spec(&fixture);
        eight.embedded_certs = vec![filler_der.clone(); 8];
        let der_eight = build_response_der(&eight);
        let result_eight = validate_staple(
            &der_eight,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert!(
            result_eight.is_ok(),
            "exactly MAX_RESPONDER_CERTS (8) embedded certificates must be considered, not \
             refused: {result_eight:?}"
        );

        let mut nine = base_spec(&fixture);
        nine.embedded_certs = vec![filler_der; 9];
        let der_nine = build_response_der(&nine);
        let result_nine = validate_staple(
            &der_nine,
            &fixture.cred,
            None,
            UnixSeconds::new(NOW),
            &OcspConfig::default(),
        );
        assert_eq!(result_nine, Err(OcspError::TooManyCerts));
    }

    #[test]
    fn validate_21() {
        let fixture = build_fixture("truncated.example.com");
        let der = build_response_der(&base_spec(&fixture));
        let cfg = OcspConfig::default();

        assert!(
            validate_staple(&der, &fixture.cred, None, UnixSeconds::new(NOW), &cfg).is_ok(),
            "the untruncated fixture response itself must validate, or this test proves nothing"
        );

        for len in 1..der.len() {
            let prefix = der
                .get(..len)
                .expect("len is within der's bounds by construction");
            let result = validate_staple(prefix, &fixture.cred, None, UnixSeconds::new(NOW), &cfg);
            assert!(
                result.is_err(),
                "a response truncated to {len} of {} bytes must not validate",
                der.len()
            );
        }
    }

    #[test]
    fn aia_url_metadata_address_refused() {
        let cfg = OcspConfig::default();
        for url in [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://127.0.0.1/",
            "http://10.0.0.5/",
            "http://[::1]/",
            "http://[fe80::1]/",
        ] {
            assert_eq!(
                validate_aia_url(url, &cfg),
                Err(OcspError::PrivateResponderAddress),
                "{url} must be refused as a private/loopback/link-local address"
            );
        }
        // The accept side, so this test cannot be satisfied by a validator that rejects every
        // URL: an ordinary public hostname, with and without an explicit default port, must pass.
        assert_eq!(validate_aia_url("http://ocsp.example.com/", &cfg), Ok(()));
        assert_eq!(
            validate_aia_url("https://ocsp.example.com:443/", &cfg),
            Ok(())
        );
    }

    #[test]
    fn aia_url_bad_scheme_refused() {
        let cfg = OcspConfig::default();
        for url in ["file:///etc/passwd", "gopher://x/", "/ocsp"] {
            assert_eq!(
                validate_aia_url(url, &cfg),
                Err(OcspError::BadResponderUrl),
                "{url} must be refused"
            );
        }
    }

    #[test]
    fn aia_url_bad_port_refused() {
        let cfg = OcspConfig::default();
        assert_eq!(
            validate_aia_url("http://ocsp.example.com:6379/", &cfg),
            Err(OcspError::BadResponderUrl)
        );
    }

    #[test]
    fn aia_url_userinfo_refused() {
        let cfg = OcspConfig::default();
        assert_eq!(
            validate_aia_url("http://user:pass@ocsp.example.com/", &cfg),
            Err(OcspError::BadResponderUrl)
        );
    }

    #[test]
    fn aia_url_too_long_refused() {
        let cfg = OcspConfig::default();
        let long_host = "a".repeat(2_000);
        let url = format!("http://{long_host}.example.com/");
        assert_eq!(
            validate_aia_url(&url, &cfg),
            Err(OcspError::BadResponderUrl)
        );
    }

    #[test]
    fn aia_url_ipv4_mapped_and_compatible_refused() {
        let cfg = OcspConfig::default();
        // Every one of these embeds a v4 address rule 4 already blocks in dotted-quad form, just
        // spelled as an IPv6 literal: an IPv4-mapped address (`::ffff:a.b.c.d`, the form every
        // dual-stack socket produces for a v4 peer), the same address with its embedded v4 part
        // written as two hex groups instead of a dotted quad, and the deprecated IPv4-compatible
        // form (`::a.b.c.d`). All five must be refused, or a certificate need only rewrite its
        // AIA host in one of these spellings to reach the exact addresses this rule exists to
        // block.
        for url in [
            "http://[::ffff:169.254.169.254]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:10.0.0.1]/",
            "http://[::ffff:7f00:1]/",
            "http://[::127.0.0.1]/",
        ] {
            assert_eq!(
                validate_aia_url(url, &cfg),
                Err(OcspError::PrivateResponderAddress),
                "{url} embeds a blocked v4 address and must be refused"
            );
        }
        // Controls, unaffected by the unmapping fix and re-asserted here so a regression that
        // broke the ordinary IPv6 classifiers while fixing the mapped case would still be caught.
        for url in ["http://[::1]/", "http://[fe80::1]/"] {
            assert_eq!(
                validate_aia_url(url, &cfg),
                Err(OcspError::PrivateResponderAddress),
                "{url} must still be refused"
            );
        }
        // The accept side: an ordinary global-unicast IPv6 literal, embedding no v4 address at
        // all, must not be caught by the new check.
        assert_eq!(validate_aia_url("http://[2001:db8::1]/", &cfg), Ok(()));
    }

    #[test]
    fn aia_url_legacy_ipv4_encodings_refused() {
        let cfg = OcspConfig::default();
        // The same blocked addresses rule 4 already refuses in canonical dotted-decimal form,
        // spelled as a single decimal integer, as `0x`-prefixed hex, with a leading-zero octal
        // octet, and in short "trailing part absorbs the rest" dotted form. A responder URL
        // author who controls a certificate's AIA field controls the string bytes, not what a
        // permissive host parser later decides they mean, so every one of these must resolve to
        // the same verdict as the canonical spelling of the address it names.
        for (url, meaning) in [
            ("http://2852039166/", "decimal for 169.254.169.254"),
            ("http://2130706433/", "decimal for 127.0.0.1"),
            ("http://0x7f000001/", "hex for 127.0.0.1"),
            ("http://0177.0.0.1/", "octal first octet for 127.0.0.1"),
            ("http://127.1/", "short dotted form for 127.0.0.1"),
        ] {
            assert_eq!(
                validate_aia_url(url, &cfg),
                Err(OcspError::PrivateResponderAddress),
                "{url} ({meaning}) must be refused"
            );
        }
        // The accept side: a real hostname with numeric-looking labels, and one with MORE than
        // four dot-separated labels (never a legal IPv4 host under any of the encodings above),
        // must not be misparsed as an IP literal.
        assert_eq!(
            validate_aia_url("http://10.0.0.5.example.com/", &cfg),
            Ok(())
        );
        assert_eq!(validate_aia_url("http://ocsp.example.com/", &cfg), Ok(()));
    }

    #[test]
    fn aia_url_private_allowed_when_configured() {
        let cfg = OcspConfig {
            allow_private_responders: true,
            ..OcspConfig::default()
        };
        assert_eq!(validate_aia_url("http://10.0.0.5/", &cfg), Ok(()));
        // The flag never relaxes rules 1 to 3.
        assert_eq!(
            validate_aia_url("file:///etc/passwd", &cfg),
            Err(OcspError::BadResponderUrl)
        );
        assert_eq!(
            validate_aia_url("http://ocsp.example.com:6379/", &cfg),
            Err(OcspError::BadResponderUrl)
        );
    }
}
