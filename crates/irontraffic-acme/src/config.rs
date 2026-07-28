// SPDX-License-Identifier: MIT OR Apache-2.0

//! ACME configuration.

use crate::account::AcmeError;
use base64::Engine;
use std::net::Ipv4Addr;

/// Maximum contacts on an account.
pub const MAX_CONTACTS: usize = 8;

/// Default directory cache TTL in seconds.
const fn d_directory_ttl() -> u32 {
    86_400
}

/// ACME configuration for one CA account.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AcmeConfig {
    /// Directory URL. Required. Must be `https` except when `allow_insecure_directory` is set,
    /// which exists only so the test suite can talk to a local pebble over http.
    pub directory_url: String,
    /// Contact addresses, each `mailto:` or a bare email which we prefix with `mailto:`.
    /// At most 8.
    #[serde(default)]
    pub contacts: Vec<String>,
    /// The operator agrees to the CA's terms of service. Required to be true for account
    /// creation; RFC 8555 makes this the client's assertion, not something we can infer.
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    /// External Account Binding, required by ZeroSSL, Google Trust Services and most commercial
    /// CAs.
    #[serde(default)]
    pub external_account_binding: Option<EabConfig>,
    /// Certificate profile name, passed through to the CA when it advertises profiles.
    #[serde(default)]
    pub profile: Option<String>,
    /// Directory cache lifetime, seconds. Default 86_400.
    #[serde(default = "d_directory_ttl")]
    pub directory_ttl_secs: u32,
    /// Permit a plaintext directory URL **on a loopback host only**. Default false. This exists so
    /// the test suite can talk to a local pebble; a non-loopback host is rejected even with the
    /// flag set, because a plaintext directory URL lets a network attacker choose the CA, the
    /// challenges and the certificate we install.
    #[serde(default)]
    pub allow_insecure_directory: bool,
}

/// External Account Binding credentials.
#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EabConfig {
    /// The key identifier the CA issued.
    pub kid: String,
    /// The base64url-encoded HMAC key the CA issued. Never logged.
    pub hmac_key: String,
}

impl core::fmt::Debug for EabConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EabConfig")
            .field("kid", &self.kid)
            .field("hmac_key", &"<redacted>")
            .finish()
    }
}

/// Extract the host portion from a URL string.
fn extract_host(url: &str) -> Option<&str> {
    let after_scheme = url.find("://")?;
    let rest = &url[after_scheme + 3..];

    // IPv6 literal: brackets enclose the whole address, skip to closing bracket.
    let host_end = if rest.starts_with('[') {
        rest.find(']').map(|pos| pos + 1)?
    } else {
        rest.find(['/', ':', '?', '#']).unwrap_or(rest.len())
    };

    if host_end == 0 {
        return None;
    }
    Some(&rest[..host_end])
}

impl AcmeConfig {
    /// Validate configuration.
    ///
    /// # Errors
    /// Any of `DirectoryUrl`, `TooManyContacts`, `ContactFormat`, `Eab`.
    pub fn validate(&self) -> Result<(), AcmeError> {
        // 1. directory_url must be https or (http + loopback + flag).
        if self.directory_url.is_empty() {
            return Err(AcmeError::DirectoryUrl);
        }
        if self.directory_url.len() > 2048 {
            return Err(AcmeError::DirectoryUrl);
        }

        let scheme_end = self
            .directory_url
            .find("://")
            .ok_or(AcmeError::DirectoryUrl)?;
        let scheme = &self.directory_url[..scheme_end];

        match scheme {
            "https" => {}
            "http" if self.allow_insecure_directory => {
                let host_str = extract_host(&self.directory_url).ok_or(AcmeError::DirectoryUrl)?;
                let is_loopback = host_str == "localhost"
                    || host_str == "[::1]"
                    || host_str.parse::<Ipv4Addr>().is_ok_and(|addr| {
                        let octets = addr.octets();
                        octets[0] == 127
                    });
                if !is_loopback {
                    return Err(AcmeError::DirectoryUrl);
                }
            }
            _ => return Err(AcmeError::DirectoryUrl),
        }

        // 2. At most 8 contacts.
        if self.contacts.len() > MAX_CONTACTS {
            return Err(AcmeError::TooManyContacts);
        }

        // 3. Each contact must be valid after normalization.
        for contact in &self.contacts {
            let normalized = if contact.starts_with("mailto:") {
                contact.clone()
            } else {
                format!("mailto:{contact}")
            };
            let bytes = normalized.as_bytes();
            if bytes.len() < 3 || bytes.len() > 254 {
                return Err(AcmeError::ContactFormat);
            }
            let at_count = bytes.iter().filter(|&&b| b == b'@').count();
            if at_count != 1 {
                return Err(AcmeError::ContactFormat);
            }
        }

        // 4. EAB validation.
        if let Some(ref eab) = self.external_account_binding {
            if eab.kid.is_empty() || eab.kid.len() > 256 {
                return Err(AcmeError::Eab);
            }
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&eab.hmac_key)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&eab.hmac_key))
                .map_err(|_| AcmeError::Eab)?;
            if decoded.len() < 16 || decoded.len() > 128 {
                return Err(AcmeError::Eab);
            }
        }

        // 5. directory_ttl_secs clamped silently.
        // No error returned for out-of-range TTL; the value is clamped at use.

        // 6. profile must be 1 to 64 printable ASCII bytes.
        if let Some(ref profile) = self.profile {
            if profile.is_empty() || profile.len() > 64 {
                return Err(AcmeError::Eab);
            }
            if !profile
                .as_bytes()
                .iter()
                .all(|&b| b.is_ascii_graphic() || b == b' ')
            {
                return Err(AcmeError::Eab);
            }
        }

        Ok(())
    }

    /// Contacts normalized to `mailto:` form.
    #[must_use]
    pub fn normalized_contacts(&self) -> Vec<String> {
        self.contacts
            .iter()
            .map(|c| {
                if c.starts_with("mailto:") {
                    c.clone()
                } else {
                    format!("mailto:{c}")
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acme_http_directory_rejected() {
        let cfg = AcmeConfig {
            directory_url: "http://acme.example.com/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: false,
        };
        assert_eq!(cfg.validate(), Err(AcmeError::DirectoryUrl));
    }

    #[test]
    fn acme_http_directory_allowed_with_flag() {
        let cfg = AcmeConfig {
            directory_url: "http://127.0.0.1:14000/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: true,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn acme_empty_directory() {
        let cfg = AcmeConfig {
            directory_url: String::new(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: false,
        };
        assert_eq!(cfg.validate(), Err(AcmeError::DirectoryUrl));
    }

    #[test]
    fn acme_long_directory() {
        let cfg = AcmeConfig {
            directory_url: "https://x.com/".repeat(300), // > 2048
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: false,
        };
        assert_eq!(cfg.validate(), Err(AcmeError::DirectoryUrl));
    }

    #[test]
    fn acme_nine_contacts() {
        let cfg = AcmeConfig {
            directory_url: "https://acme.example.com/dir".into(),
            contacts: vec![
                "a@b.com".into(),
                "a@b.com".into(),
                "a@b.com".into(),
                "a@b.com".into(),
                "a@b.com".into(),
                "a@b.com".into(),
                "a@b.com".into(),
                "a@b.com".into(),
                "a@b.com".into(),
            ],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: false,
        };
        assert_eq!(cfg.validate(), Err(AcmeError::TooManyContacts));
    }

    #[test]
    fn acme_contact_normalized() {
        let cfg = AcmeConfig {
            directory_url: "https://acme.example.com/dir".into(),
            contacts: vec!["ops@example.com".into()],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: false,
        };
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.normalized_contacts(), vec!["mailto:ops@example.com"]);
    }

    #[test]
    fn acme_tel_contact_rejected() {
        let cfg = AcmeConfig {
            directory_url: "https://acme.example.com/dir".into(),
            contacts: vec!["tel:+15551234".into()],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: false,
        };
        assert_eq!(cfg.validate(), Err(AcmeError::ContactFormat));
    }

    #[test]
    fn acme_insecure_directory_non_loopback_rejected() {
        // http://acme.example.com/dir with flag set
        let cfg1 = AcmeConfig {
            directory_url: "http://acme.example.com/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: true,
        };
        assert_eq!(cfg1.validate(), Err(AcmeError::DirectoryUrl));

        // http://10.0.0.5/dir with flag set
        let cfg2 = AcmeConfig {
            directory_url: "http://10.0.0.5/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: true,
        };
        assert_eq!(cfg2.validate(), Err(AcmeError::DirectoryUrl));

        // http://127.0.0.1:14000/dir with flag set -- should be OK
        let cfg3 = AcmeConfig {
            directory_url: "http://127.0.0.1:14000/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: true,
        };
        assert!(cfg3.validate().is_ok());

        // http://[::1]/dir with flag set
        let cfg4 = AcmeConfig {
            directory_url: "http://[::1]/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: true,
        };
        assert!(cfg4.validate().is_ok());

        // http://localhost/dir with flag set
        let cfg5 = AcmeConfig {
            directory_url: "http://localhost/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: true,
        };
        assert!(cfg5.validate().is_ok());
    }

    #[test]
    fn acme_eab_bad_base64() {
        let cfg = AcmeConfig {
            directory_url: "https://acme.example.com/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: Some(EabConfig {
                kid: "kid-1".into(),
                hmac_key: "!!!not-base64!!!".into(),
            }),
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: false,
        };
        assert_eq!(cfg.validate(), Err(AcmeError::Eab));
    }

    #[test]
    fn acme_eab_short_key() {
        // 8 bytes encoded is a short base64url string.
        let short_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 8]);
        let cfg = AcmeConfig {
            directory_url: "https://acme.example.com/dir".into(),
            contacts: vec![],
            terms_of_service_agreed: true,
            external_account_binding: Some(EabConfig {
                kid: "kid-1".into(),
                hmac_key: short_b64,
            }),
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: false,
        };
        assert_eq!(cfg.validate(), Err(AcmeError::Eab));
    }
}
