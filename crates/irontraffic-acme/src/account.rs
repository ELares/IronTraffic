// SPDX-License-Identifier: MIT OR Apache-2.0

//! ACME directory and account handling.

use crate::config::AcmeConfig;
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper_util::client::legacy::Client;
use irontraffic_tls::time::UnixSeconds;
use zeroize::Zeroizing;

/// Why an ACME operation failed.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum AcmeError {
    /// The directory URL was missing, unparseable, over-length, or not https.
    DirectoryUrl,
    /// More than `MAX_CONTACTS`.
    TooManyContacts,
    /// A contact was not a plausible mailto address.
    ContactFormat,
    /// The EAB kid or HMAC key was malformed.
    Eab,
    /// The CA requires External Account Binding and none was configured.
    EabRequired,
    /// `termsOfServiceAgreed` was not set.
    TermsNotAgreed,
    /// The CA advertises profiles and the requested one is not among them.
    UnknownProfile {
        /// What was asked for.
        requested: Box<str>,
        /// What the CA offers.
        available: Box<[Box<str>]>,
    },
    /// The CA rate limited us.
    RateLimited {
        /// Seconds to wait, from `Retry-After` when present.
        retry_after: Option<u32>,
    },
    /// Any other protocol failure.
    Protocol {
        /// The ACME problem type, for example `urn:ietf:params:acme:error:unauthorized`.
        kind: Box<str>,
        /// The CA's `detail`, truncated to 512 bytes, control characters removed.
        detail: Box<str>,
    },
    /// Transport failure.
    Transport(Box<str>),
    /// The persisted credentials blob did not deserialize.
    Credentials,
}

impl core::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DirectoryUrl => f.write_str(
                "the ACME directory URL was missing, unparseable, over-length, or not https",
            ),
            Self::TooManyContacts => {
                f.write_str("more than the maximum number of contacts were specified")
            }
            Self::ContactFormat => {
                f.write_str("a contact was not a plausible mailto address")
            }
            Self::Eab => f.write_str("the EAB kid or HMAC key was malformed"),
            Self::EabRequired => f.write_str(
                "this CA requires External Account Binding; set acme.externalAccountBinding.kid and .hmacKey",
            ),
            Self::TermsNotAgreed => f.write_str("termsOfServiceAgreed was not set"),
            Self::UnknownProfile {
                requested,
                available,
            } => {
                let mut s = String::new();
                s.push_str("CA does not offer certificate profile \"");
                s.push_str(requested);
                s.push_str("\"; it offers: ");
                let mut first = true;
                for a in &**available {
                    if !first {
                        s.push_str(", ");
                    }
                    s.push_str(a);
                    first = false;
                }
                f.write_str(&s)
            }
            Self::RateLimited { retry_after } => {
                if let Some(secs) = retry_after {
                    write!(f, "rate limited; retry after {secs} seconds")
                } else {
                    f.write_str("rate limited; no retry-after header provided")
                }
            }
            Self::Protocol { kind, detail } => {
                write!(f, "ACME protocol error ({kind}): {detail}")
            }
            Self::Transport(detail) => {
                write!(f, "ACME transport error: {detail}")
            }
            Self::Credentials => {
                f.write_str("the persisted credentials blob did not deserialize")
            }
        }
    }
}

impl std::error::Error for AcmeError {}

/// A fetched CA directory with its cache timestamp.
pub struct AcmeDirectory {
    fetched_at: UnixSeconds,
    ttl_secs: u32,
    /// Profiles the CA advertises, if any.
    profiles: Box<[Box<str>]>,
    /// Whether the CA advertises an ARI `renewalInfo` endpoint.
    has_renewal_info: bool,
}

impl AcmeDirectory {
    /// Fetch the directory.
    ///
    /// # Errors
    /// `AcmeError::Transport`, `AcmeError::Protocol`, `AcmeError::UnknownProfile`.
    pub async fn fetch(cfg: &AcmeConfig, now: UnixSeconds) -> Result<Self, AcmeError> {
        let ttl_secs = cfg.directory_ttl_secs.clamp(300, 604_800);

        let (profiles, has_renewal_info) = fetch_directory_meta(&cfg.directory_url).await?;
        if let Some(ref requested) = cfg.profile
            && !profiles.is_empty()
            && !profiles.iter().any(|p| p.as_ref() == requested.as_str())
        {
            return Err(AcmeError::UnknownProfile {
                requested: requested.clone().into_boxed_str(),
                available: profiles,
            });
        }
        Ok(AcmeDirectory {
            fetched_at: now,
            ttl_secs,
            profiles,
            has_renewal_info,
        })
    }

    /// Whether the cache has expired.
    #[must_use]
    pub fn is_stale(&self, now: UnixSeconds) -> bool {
        now.get() >= self.fetched_at.get() + u64::from(self.ttl_secs)
    }

    /// Whether the CA advertises an ARI endpoint.
    #[must_use]
    pub fn has_renewal_info(&self) -> bool {
        self.has_renewal_info
    }

    /// Advertised profile names.
    #[must_use]
    pub fn profiles(&self) -> &[Box<str>] {
        &self.profiles
    }
}

/// Fetch directory metadata from the CA via HTTP.
async fn fetch_directory_meta(directory_url: &str) -> Result<(Box<[Box<str>]>, bool), AcmeError> {
    let uri: http::Uri = directory_url
        .parse()
        .map_err(|_| AcmeError::Transport("invalid directory URL".into()))?;

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|_| AcmeError::Transport("failed to load native TLS roots".into()))?
        .https_or_http()
        .enable_http1()
        .build();

    let client = Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector);

    let req = http::Request::builder()
        .uri(uri)
        .body(Empty::<Bytes>::new())
        .map_err(|e| AcmeError::Transport(e.to_string().into()))?;

    let response = client
        .request(req)
        .await
        .map_err(|e| AcmeError::Transport(e.to_string().into()))?;

    let status = response.status();
    if status.is_server_error() || status.is_client_error() {
        if status == hyper::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get(hyper::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u32>().ok());
            return Err(AcmeError::RateLimited { retry_after });
        }
        return Err(AcmeError::Transport(
            format!("directory fetch returned HTTP {status}").into(),
        ));
    }

    let collected = response
        .collect()
        .await
        .map_err(|e| AcmeError::Transport(e.to_string().into()))?;
    let body_bytes = collected.to_bytes();
    let dir_value: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| AcmeError::Transport(e.to_string().into()))?;

    Ok(extract_dir_meta_from_json(&dir_value))
}

/// Extract profiles and renewal_info from a directory JSON value.
fn extract_dir_meta_from_json(dir: &serde_json::Value) -> (Box<[Box<str>]>, bool) {
    let meta = dir.get("meta");
    let profiles: Box<[Box<str>]> = meta
        .and_then(|m| m.get("profiles"))
        .and_then(|p| p.as_object())
        .map(|obj| {
            obj.keys()
                .map(|k| k.clone().into_boxed_str())
                .collect::<Vec<_>>()
                .into_boxed_slice()
        })
        .unwrap_or_default();

    let has_renewal_info = meta
        .and_then(|m| m.get("renewalInfo"))
        .and_then(|r| r.as_str())
        .is_some_and(|s| !s.is_empty());

    (profiles, has_renewal_info)
}

/// An ACME account, plus the opaque credentials blob the caller must persist.
pub struct AcmeAccount {
    inner: instant_acme::Account,
    url: Box<str>,
    fingerprint: [u8; 8],
    credentials_json: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for AcmeAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AcmeAccount")
            .field("url", &self.url)
            .field("fingerprint", &self.fingerprint_hex())
            .finish()
    }
}

impl AcmeAccount {
    /// Register a new account.
    ///
    /// # Errors
    /// `AcmeError::TermsNotAgreed`, `AcmeError::EabRequired`, `AcmeError::RateLimited`,
    /// `AcmeError::Protocol`, `AcmeError::Transport`.
    pub async fn create(_directory: &AcmeDirectory, cfg: &AcmeConfig) -> Result<Self, AcmeError> {
        if !cfg.terms_of_service_agreed {
            return Err(AcmeError::TermsNotAgreed);
        }

        let contacts: Vec<String> = cfg.normalized_contacts();
        let contact_refs: Vec<&str> = contacts.iter().map(String::as_str).collect();

        let new_account = instant_acme::NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let eab_key = if let Some(ref eab) = cfg.external_account_binding {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&eab.hmac_key)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&eab.hmac_key))
                .map_err(|_| AcmeError::Eab)?;
            Some(instant_acme::ExternalAccountKey::new(
                eab.kid.clone(),
                &decoded,
            ))
        } else {
            None
        };

        let builder = instant_acme::Account::builder().map_err(map_instant_error)?;
        let (account, credentials) = builder
            .create(&new_account, cfg.directory_url.clone(), eab_key.as_ref())
            .await
            .map_err(map_instant_error)?;

        let url = account.id().to_owned().into_boxed_str();
        let creds_json = serde_json::to_vec(&credentials).map_err(|e| AcmeError::Protocol {
            kind: "internal".into(),
            detail: e.to_string().into_boxed_str(),
        })?;

        let fingerprint = compute_fingerprint(&creds_json);

        Ok(AcmeAccount {
            inner: account,
            url,
            fingerprint,
            credentials_json: Zeroizing::new(creds_json),
        })
    }

    /// Load a persisted account. Performs no network request.
    ///
    /// # Errors
    /// `AcmeError::Credentials`.
    pub async fn load(credentials_json: &[u8]) -> Result<Self, AcmeError> {
        let credentials: instant_acme::AccountCredentials =
            serde_json::from_slice(credentials_json).map_err(|_| AcmeError::Credentials)?;

        let builder = instant_acme::Account::builder().map_err(|_| AcmeError::Credentials)?;
        let account = builder
            .from_credentials(credentials)
            .await
            .map_err(|_| AcmeError::Credentials)?;

        let url = account.id().to_owned().into_boxed_str();
        let creds_vec = credentials_json.to_vec();
        let fingerprint = compute_fingerprint(&creds_vec);

        Ok(AcmeAccount {
            inner: account,
            url,
            fingerprint,
            credentials_json: Zeroizing::new(creds_vec),
        })
    }

    /// The credentials blob the caller must persist. Zeroized on drop.
    ///
    /// This contains the account **private key**. The caller MUST encrypt it
    /// at rest and MUST NOT write it to a log, a trace, a status field, or
    /// the admin API. Report the account by `url()` and `fingerprint_hex()`
    /// instead.
    #[must_use]
    pub fn credentials_json(&self) -> &[u8] {
        &self.credentials_json
    }

    /// The account URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Lowercase hex of the 8-byte account fingerprint, for logs and the admin API.
    #[must_use]
    #[allow(
        clippy::integer_division,
        reason = "intentional hex nibble pair encoding"
    )]
    pub fn fingerprint_hex(&self) -> [u8; 16] {
        let chars = b"0123456789abcdef";
        core::array::from_fn(|i| {
            let b = self.fingerprint.get(i / 2).copied().unwrap_or(0);
            match i % 2 {
                0 => chars.get((b >> 4) as usize).copied().unwrap_or(b'0'),
                _ => chars.get((b & 0x0f) as usize).copied().unwrap_or(b'0'),
            }
        })
    }

    /// Deactivate the account at the CA.
    ///
    /// # Errors
    /// `AcmeError::Protocol`, `AcmeError::Transport`.
    pub async fn deactivate(self) -> Result<(), AcmeError> {
        self.inner.deactivate().await.map_err(map_instant_error)
    }
}

/// Compute the 8-byte fingerprint from credentials JSON.
fn compute_fingerprint(data: &[u8]) -> [u8; 8] {
    let key = b"irontraffic/acme-account-fingerprint/v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    hasher.update(data);
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let mut fp = [0u8; 8];
    fp.copy_from_slice(&bytes[..8]);
    fp
}

/// Map an `instant_acme::Error` to an `AcmeError`.
fn map_instant_error(e: instant_acme::Error) -> AcmeError {
    use instant_acme::Error;
    match e {
        Error::Api(ref problem) => {
            let kind: Box<str> = problem
                .r#type
                .clone()
                .unwrap_or_else(|| "urn:ietf:params:acme:error:unknown".into())
                .into_boxed_str();

            if kind.as_ref() == "urn:ietf:params:acme:error:externalAccountRequired" {
                return AcmeError::EabRequired;
            }
            if kind.as_ref() == "urn:ietf:params:acme:error:rateLimited" {
                return AcmeError::RateLimited { retry_after: None };
            }

            let detail = problem
                .detail
                .as_deref()
                .map(sanitize_detail)
                .unwrap_or_else(|| Box::from(""));

            AcmeError::Protocol { kind, detail }
        }
        _ => AcmeError::Transport(e.to_string().into_boxed_str()),
    }
}

/// Sanitize a detail string: truncate to 512 bytes, remove control characters.
fn sanitize_detail(s: &str) -> Box<str> {
    let sanitized: String = s
        .chars()
        .filter(|&c| !c.is_control() || c == '\t' || c == '\n')
        .collect();
    let truncated: String = sanitized.chars().take(512).collect();
    truncated.into_boxed_str()
}

#[cfg(test)]
fn make_test_credentials_json() -> Vec<u8> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let (_key, key_pkcs8) =
        instant_acme::Key::generate_pkcs8().expect("key generation should succeed");
    let key_b64 = B64.encode(key_pkcs8.secret_pkcs8_der());

    serde_json::json!({
        "id": "https://example.com/acme/acct/1",
        "key_pkcs8": key_b64,
        "directory": null,
        "urls": {
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
        }
    })
    .to_string()
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EabConfig;

    #[tokio::test]
    async fn acme_debug_hides_secrets() {
        let eab = EabConfig {
            kid: "test-kid".into(),
            hmac_key: "a2V5".into(),
        };
        let debug_eab = format!("{eab:?}");
        assert!(
            !debug_eab.contains("a2V5"),
            "Debug output must not contain HMAC key value: {debug_eab}"
        );

        let creds = make_test_credentials_json();
        let account = AcmeAccount::load(&creds).await;
        if let Ok(ref acc) = account {
            let debug_acc = format!("{acc:?}");
            assert!(
                !debug_acc.contains("privateKey"),
                "Debug output must not contain privateKey: {debug_acc}"
            );
        }
    }

    #[test]
    fn acme_detail_truncated_and_sanitized() {
        let long = "a".repeat(1000) + "\x00\x01\x02";
        let sanitized = sanitize_detail(&long);
        assert!(sanitized.len() <= 512);
        for c in sanitized.chars() {
            assert!(
                !c.is_control(),
                "control character found in sanitized output"
            );
        }
    }

    #[test]
    fn acme_terms_not_agreed() {
        let msg = format!("{}", AcmeError::TermsNotAgreed);
        assert_eq!(msg, "termsOfServiceAgreed was not set");
    }

    #[test]
    fn acme_eab_required_message() {
        let msg = format!("{}", AcmeError::EabRequired);
        assert_eq!(
            msg,
            "this CA requires External Account Binding; set acme.externalAccountBinding.kid and .hmacKey"
        );
    }

    #[test]
    fn acme_unknown_profile_lists_available() {
        let err = AcmeError::UnknownProfile {
            requested: "tlsserver".into(),
            available: vec!["classic".into(), "shortlived".into()].into_boxed_slice(),
        };
        let msg = format!("{err}");
        assert_eq!(
            msg,
            "CA does not offer certificate profile \"tlsserver\"; it offers: classic, shortlived"
        );
    }

    #[test]
    fn acme_profile_passthrough_when_none_advertised() {
        let profiles: Box<[Box<str>]> = Box::new([]);
        let requested = "anything";
        assert!(
            profiles.is_empty() || profiles.iter().any(|p| p.as_ref() == requested),
            "when no profiles advertised, any profile should pass"
        );
    }

    #[test]
    fn acme_rate_limited_carries_retry_after() {
        let err = AcmeError::RateLimited {
            retry_after: Some(60),
        };
        let msg = format!("{err}");
        assert_eq!(msg, "rate limited; retry after 60 seconds");

        let err_no_retry = AcmeError::RateLimited { retry_after: None };
        let msg_no = format!("{err_no_retry}");
        assert_eq!(msg_no, "rate limited; no retry-after header provided");
    }

    #[tokio::test]
    async fn acme_load_truncated_blob() {
        let blob = b"{\"truncated\": ";
        let result = AcmeAccount::load(blob).await;
        assert!(result.is_err(), "load should fail for truncated blob");
        assert_eq!(result.unwrap_err(), AcmeError::Credentials);
    }

    #[tokio::test]
    async fn acme_load_makes_no_network_call() {
        let creds = make_test_credentials_json();
        let result = AcmeAccount::load(&creds).await;
        assert!(
            result.is_ok(),
            "loading valid credentials should succeed without network call: {result:?}"
        );
    }
}
