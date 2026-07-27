// SPDX-License-Identifier: MIT OR Apache-2.0

//! Configuration types for ACME account and directory lifecycle.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

/// Maximum contacts on an account.
pub const MAX_CONTACTS: usize = 8;

/// Default directory cache lifetime, in seconds.
const DEFAULT_DIRECTORY_TTL: u32 = 86_400;

/// Minimum directory cache lifetime, in seconds.
const MIN_DIRECTORY_TTL: u32 = 300;

/// Maximum directory cache lifetime, in seconds.
const MAX_DIRECTORY_TTL: u32 = 604_800;

/// The prefix used to fingerprint account credentials.
const ACCOUNT_FINGERPRINT_PREFIX: &[u8] = b"irontraffic/acme-account-fingerprint/v1";

/// External Account Binding credentials.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EabConfig {
    /// The key identifier the CA issued.
    pub kid: String,
    /// The base64url-encoded HMAC key the CA issued. Never logged.
    pub hmac_key: String,
}

impl EabConfig {
    /// Decode the HMAC key and validate the credentials.
    ///
    /// # Errors
    /// `AcmeError::Eab` if the key id or HMAC key is malformed.
    fn validate(&self) -> Result<Vec<u8>, crate::AcmeError> {
        if self.kid.is_empty() || self.kid.len() > 256 {
            return Err(crate::AcmeError::Eab);
        }

        let mut bytes = URL_SAFE_NO_PAD
            .decode(&self.hmac_key)
            .or_else(|_| URL_SAFE.decode(&self.hmac_key))
            .map_err(|_| crate::AcmeError::Eab)?;
        if (16..=128).contains(&bytes.len()) {
            return Ok(bytes);
        }

        bytes.zeroize();
        Err(crate::AcmeError::Eab)
    }
}

impl fmt::Debug for EabConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EabConfig")
            .field("kid", &self.kid)
            .field("hmac_key", &"<redacted>")
            .finish()
    }
}

/// ACME configuration for one CA account.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AcmeConfig {
    /// Directory URL. Required. Must be `https://` except when `allow_insecure_directory` is set.
    pub directory_url: String,
    /// Contact addresses, each `mailto:` or a bare email which we prefix with `mailto:`.
    /// At most 8.
    #[serde(default)]
    pub contacts: Vec<String>,
    /// The operator agrees to the CA's terms of service.
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    /// External Account Binding.
    #[serde(default)]
    pub external_account_binding: Option<EabConfig>,
    /// Certificate profile name.
    #[serde(default)]
    pub profile: Option<String>,
    /// Directory cache lifetime, seconds.
    #[serde(default = "d_directory_ttl")]
    pub directory_ttl_secs: u32,
    /// Permit a plaintext directory URL on a loopback host only.
    #[serde(default)]
    pub allow_insecure_directory: bool,
}

/// Serde default for `directory_ttl_secs`.
fn d_directory_ttl() -> u32 {
    DEFAULT_DIRECTORY_TTL
}

impl AcmeConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    /// Any of `DirectoryUrl`, `TooManyContacts`, `ContactFormat`, or `Eab`.
    pub fn validate(&self) -> Result<(), crate::AcmeError> {
        validate_directory_url(&self.directory_url, self.allow_insecure_directory)?;

        if self.directory_url.len() > 2_048 {
            return Err(crate::AcmeError::DirectoryUrl);
        }

        if self.contacts.len() > MAX_CONTACTS {
            return Err(crate::AcmeError::TooManyContacts);
        }

        for contact in &self.contacts {
            let normalized = normalize_contact(contact).ok_or(crate::AcmeError::ContactFormat)?;
            let bytes = normalized.as_bytes();
            if bytes.len() < 3 || bytes.len() > 254 || normalized.matches('@').count() != 1 {
                return Err(crate::AcmeError::ContactFormat);
            }
        }

        if let Some(eab) = &self.external_account_binding {
            let _ = eab.validate()?;
        }

        if let Some(profile) = &self.profile {
            if profile.is_empty() || profile.len() > 64 || !profile.bytes().all(is_printable_ascii)
            {
                return Err(crate::AcmeError::DirectoryUrl);
            }
        }

        let _ = self
            .directory_ttl_secs
            .clamp(MIN_DIRECTORY_TTL, MAX_DIRECTORY_TTL);
        Ok(())
    }

    /// Contacts normalized to `mailto:` form.
    #[must_use]
    pub fn normalized_contacts(&self) -> Vec<String> {
        self.contacts
            .iter()
            .filter_map(|c| normalize_contact(c))
            .collect()
    }
}

/// True if the byte is a printable ASCII character.
fn is_printable_ascii(b: u8) -> bool {
    b.is_ascii_graphic()
}

/// Normalize a contact address to `mailto:` form, rejecting non-mailto schemes.
fn normalize_contact(contact: &str) -> Option<String> {
    if contact.starts_with("mailto:") {
        return Some(contact.to_owned());
    }

    if contact.contains('@') && !contact.contains(':') {
        return Some(format!("mailto:{contact}"));
    }

    None
}

/// Validate the directory URL.
fn validate_directory_url(url: &str, allow_insecure: bool) -> Result<(), crate::AcmeError> {
    if url.is_empty() {
        return Err(crate::AcmeError::DirectoryUrl);
    }

    let Some(after_scheme) = url.split_once("://") else {
        return Err(crate::AcmeError::DirectoryUrl);
    };

    let scheme = after_scheme.0.to_ascii_lowercase();
    if scheme == "https" {
        return Ok(());
    }

    if scheme == "http" && allow_insecure && is_loopback_url(url) {
        tracing::warn!("allowing insecure plaintext ACME directory URL for loopback: {url}");
        return Ok(());
    }

    Err(crate::AcmeError::DirectoryUrl)
}

/// True if the URL's host is a loopback address or the literal name `localhost`.
fn is_loopback_url(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };

    let authority = rest.split('/').next().unwrap_or(rest);
    let host = if authority.starts_with('[') {
        let Some((ip, _)) = authority.split_once(']') else {
            return false;
        };
        ip.strip_prefix('[').unwrap_or(ip)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }

    false
}

/// Compute the 8-byte fingerprint of an account credentials blob.
#[must_use]
pub(crate) fn fingerprint_of(credentials_json: &[u8]) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ACCOUNT_FINGERPRINT_PREFIX);
    hasher.update(credentials_json);
    let hash = *hasher.finalize().as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

/// Lowercase hex encoding of an 8-byte fingerprint.
#[must_use]
pub(crate) fn fingerprint_hex(fingerprint: [u8; 8]) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for (i, byte) in fingerprint.iter().enumerate() {
        out[2 * i] = HEX[usize::from(byte >> 4)];
        out[2 * i + 1] = HEX[usize::from(byte & 0x0f)];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AcmeError;

    fn config_with_directory(directory_url: &str) -> AcmeConfig {
        AcmeConfig {
            directory_url: directory_url.to_owned(),
            contacts: Vec::new(),
            terms_of_service_agreed: false,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: DEFAULT_DIRECTORY_TTL,
            allow_insecure_directory: false,
        }
    }

    fn config_with_directory_and_flag(directory_url: &str) -> AcmeConfig {
        AcmeConfig {
            directory_url: directory_url.to_owned(),
            contacts: Vec::new(),
            terms_of_service_agreed: false,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: DEFAULT_DIRECTORY_TTL,
            allow_insecure_directory: true,
        }
    }

    fn config_with_contacts(contacts: Vec<String>) -> AcmeConfig {
        AcmeConfig {
            directory_url: "https://acme.example.com/dir".to_owned(),
            contacts,
            terms_of_service_agreed: false,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: DEFAULT_DIRECTORY_TTL,
            allow_insecure_directory: false,
        }
    }

    fn eab_config(hmac_key: &str) -> AcmeConfig {
        AcmeConfig {
            directory_url: "https://acme.example.com/dir".to_owned(),
            contacts: Vec::new(),
            terms_of_service_agreed: false,
            external_account_binding: Some(EabConfig {
                kid: "kid".to_owned(),
                hmac_key: hmac_key.to_owned(),
            }),
            profile: None,
            directory_ttl_secs: DEFAULT_DIRECTORY_TTL,
            allow_insecure_directory: false,
        }
    }

    #[test]
    fn acme_http_directory_rejected() {
        let cfg = config_with_directory("http://127.0.0.1:14000/dir");
        assert_eq!(cfg.validate(), Err(AcmeError::DirectoryUrl));
    }

    #[test]
    fn acme_http_directory_allowed_with_flag() {
        let cfg = config_with_directory_and_flag("http://127.0.0.1:14000/dir");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn acme_empty_directory() {
        let cfg = config_with_directory("");
        assert_eq!(cfg.validate(), Err(AcmeError::DirectoryUrl));
    }

    #[test]
    fn acme_long_directory() {
        let url = format!("https://acme.example.com/{}", "a".repeat(2_040));
        let cfg = config_with_directory(&url);
        assert_eq!(cfg.validate(), Err(AcmeError::DirectoryUrl));
    }

    #[test]
    fn acme_nine_contacts() {
        let contacts = (0..9).map(|i| format!("ops{i}@example.com")).collect();
        let cfg = config_with_contacts(contacts);
        assert_eq!(cfg.validate(), Err(AcmeError::TooManyContacts));
    }

    #[test]
    fn acme_contact_normalized() {
        let cfg = config_with_contacts(vec!["ops@example.com".to_owned()]);
        assert_eq!(
            cfg.normalized_contacts(),
            vec!["mailto:ops@example.com".to_owned()]
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn acme_tel_contact_rejected() {
        let cfg = config_with_contacts(vec!["tel:+15551234".to_owned()]);
        assert_eq!(cfg.validate(), Err(AcmeError::ContactFormat));
    }

    #[test]
    fn acme_eab_bad_base64() {
        let cfg = eab_config("not-base64!!!");
        assert_eq!(cfg.validate(), Err(AcmeError::Eab));
    }

    #[test]
    fn acme_eab_short_key() {
        let cfg = eab_config("aGVsbG8="); // 5 bytes
        assert_eq!(cfg.validate(), Err(AcmeError::Eab));
    }

    #[test]
    fn acme_insecure_directory_non_loopback_rejected() {
        for url in ["http://acme.example.com/dir", "http://10.0.0.5/dir"] {
            let cfg = config_with_directory_and_flag(url);
            assert_eq!(cfg.validate(), Err(AcmeError::DirectoryUrl));
        }

        for url in [
            "http://127.0.0.1:14000/dir",
            "http://[::1]/dir",
            "http://localhost/dir",
        ] {
            let cfg = config_with_directory_and_flag(url);
            assert!(cfg.validate().is_ok());
        }
    }
}
