// SPDX-License-Identifier: MIT OR Apache-2.0

//! ACME directory and account lifecycle.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, StatusCode};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, BodyWrapper, BytesResponse, ExternalAccountKey,
    HttpClient, NewAccount,
};
use irontraffic_tls::time::UnixSeconds;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{fingerprint_hex, fingerprint_of, EabConfig, MAX_CONTACTS};
use crate::AcmeConfig;

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
        /// The ACME problem type.
        kind: Box<str>,
        /// The CA's `detail`, truncated to 512 bytes, control characters removed.
        detail: Box<str>,
    },
    /// Transport failure.
    Transport(Box<str>),
    /// The persisted credentials blob did not deserialize.
    Credentials,
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectoryUrl => {
                f.write_str("directory URL was missing, unparseable, over-length, or not https")
            }
            Self::TooManyContacts => f.write_str("more than 8 contacts"),
            Self::ContactFormat => f.write_str("contact was not a plausible mailto address"),
            Self::Eab => f.write_str("EAB kid or HMAC key was malformed"),
            Self::EabRequired => f.write_str(
                "this CA requires External Account Binding; \
                 set acme.externalAccountBinding.kid and .hmacKey",
            ),
            Self::TermsNotAgreed => f.write_str("terms of service agreement was not asserted"),
            Self::UnknownProfile { requested, available } => {
                let joined = available
                    .iter()
                    .map(|s| s.as_ref())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "CA does not offer certificate profile \"{requested}\"; it offers: {joined}"
                )
            }
            Self::RateLimited { retry_after: None } => f.write_str("rate limited by the CA"),
            Self::RateLimited { retry_after: Some(secs) } => {
                write!(f, "rate limited by the CA; retry after {secs} seconds")
            }
            Self::Protocol { kind, detail } => {
                write!(f, "ACME protocol error {kind}: {detail}")
            }
            Self::Transport(msg) => write!(f, "transport failure: {msg}"),
            Self::Credentials => f.write_str("persisted account credentials did not deserialize"),
        }
    }
}

impl std::error::Error for AcmeError {}

/// A fetched CA directory with its cache timestamp.
pub struct AcmeDirectory {
    directory_url: Box<str>,
    directory_bytes: Bytes,
    fetched_at: UnixSeconds,
    ttl_secs: u32,
    profiles: Box<[Box<str>]>,
    has_renewal_info: bool,
}

impl fmt::Debug for AcmeDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeDirectory")
            .field("directory_url", &self.directory_url)
            .field("fetched_at", &self.fetched_at)
            .field("ttl_secs", &self.ttl_secs)
            .field("profiles", &self.profiles)
            .field("has_renewal_info", &self.has_renewal_info)
            .finish()
    }
}

impl AcmeDirectory {
    /// Fetch the directory.
    ///
    /// # Errors
    /// `AcmeError::Transport`, `AcmeError::Protocol`, `AcmeError::UnknownProfile`.
    pub async fn fetch(cfg: &AcmeConfig, now: UnixSeconds) -> Result<Self, AcmeError> {
        cfg.validate()?;

        let client = HttpClientImpl::new().await?;
        let request = Request::builder()
            .method(Method::GET)
            .uri(cfg.directory_url.as_str())
            .body(BodyWrapper::default())
            .map_err(|e| AcmeError::Transport(e.to_string().into_boxed_str()))?;

        let response = HttpClient::request(&client, request)
            .await
            .map_err(map_directory_error)?;
        let bytes = response
            .body()
            .await
            .map_err(|e| AcmeError::Transport(e.to_string().into_boxed_str()))?;

        if !response.parts.status.is_success() {
            return Err(protocol_error_from_response(&bytes, response.parts.status));
        }

        let directory: Directory = serde_json::from_slice(&bytes).map_err(|e| {
            AcmeError::Protocol {
                kind: "malformed-directory".into(),
                detail: sanitize_detail(&e.to_string()),
            }
        })?;

        let profiles: Box<[Box<str>]> = directory
            .meta
            .profiles
            .keys()
            .map(|s| s.clone().into_boxed_str())
            .collect();

        if let Some(requested) = &cfg.profile {
            if !profiles.is_empty() && !profiles.iter().any(|p| p.as_ref() == requested) {
                return Err(AcmeError::UnknownProfile {
                    requested: requested.clone().into_boxed_str(),
                    available: profiles,
                });
            }
        }

        let has_renewal_info = directory.renewal_info.is_some();
        let ttl_secs = cfg.directory_ttl_secs.clamp(300, 604_800);

        Ok(Self {
            directory_url: cfg.directory_url.clone().into_boxed_str(),
            directory_bytes: bytes,
            fetched_at: now,
            ttl_secs,
            profiles,
            has_renewal_info,
        })
    }

    /// Whether the cache has expired.
    #[must_use]
    pub fn is_stale(&self, now: UnixSeconds) -> bool {
        let expiry = self.fetched_at.saturating_add_secs(u64::from(self.ttl_secs));
        now >= expiry
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

/// An ACME account, plus the opaque credentials blob the caller must persist.
pub struct AcmeAccount {
    inner: Option<Account>,
    url: Box<str>,
    fingerprint: [u8; 8],
    credentials_json: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AcmeAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = String::from_utf8_lossy(&fingerprint_hex(self.fingerprint));
        f.debug_struct("AcmeAccount")
            .field("url", &self.url)
            .field("fingerprint", &hex.as_ref())
            .finish()
    }
}

impl AcmeAccount {
    /// Register a new account.
    ///
    /// # Errors
    /// `AcmeError::TermsNotAgreed`, `AcmeError::EabRequired`, `AcmeError::RateLimited`,
    /// `AcmeError::Protocol`, `AcmeError::Transport`.
    pub async fn create(directory: &AcmeDirectory, cfg: &AcmeConfig) -> Result<Self, AcmeError> {
        if !cfg.terms_of_service_agreed {
            return Err(AcmeError::TermsNotAgreed);
        }
        cfg.validate()?;

        let contacts = cfg.normalized_contacts();
        let contact_refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let external_account = match &cfg.external_account_binding {
            Some(eab) => {
                let key = eab.validate().map_err(|_| AcmeError::Eab)?;
                Some(ExternalAccountKey::new(eab.kid.clone(), &key))
            }
            None => None,
        };

        let client = HttpClientImpl::new()
            .await?
            .with_directory_cache(
                directory.directory_url.to_string(),
                directory.directory_bytes.clone(),
            );
        let rate_client = RateLimitClient::new(client);
        let retry_after = rate_client.retry_after.clone();
        let builder = Account::builder_with_http(Box::new(rate_client));

        let (account, credentials) = builder
            .create(
                &new_account,
                directory.directory_url.to_string(),
                external_account.as_ref(),
            )
            .await
            .map_err(|e| map_create_error(e, retry_after))?;

        let account_url = account.id().to_owned();
        let directory = parse_directory(&directory.directory_bytes)?;
        let envelope = CredentialsEnvelope {
            credentials,
            directory,
            directory_url: directory.directory_url.to_string(),
            account_url: account_url.clone(),
        };
        let credentials_json = serde_json::to_vec(&envelope)
            .map_err(|_| AcmeError::Credentials)?;
        let fingerprint = fingerprint_of(&credentials_json);

        Ok(Self {
            inner: Some(account),
            url: account_url.into_boxed_str(),
            fingerprint,
            credentials_json: Zeroizing::new(credentials_json),
        })
    }

    /// Load a persisted account. Performs no network request.
    ///
    /// # Errors
    /// `AcmeError::Credentials`.
    pub fn load(credentials_json: &[u8]) -> Result<Self, AcmeError> {
        let envelope: CredentialsEnvelope =
            serde_json::from_slice(credentials_json).map_err(|_| AcmeError::Credentials)?;
        let fingerprint = fingerprint_of(credentials_json);
        Ok(Self {
            inner: None,
            url: envelope.account_url.into_boxed_str(),
            fingerprint,
            credentials_json: Zeroizing::new(credentials_json.to_vec()),
        })
    }

    /// The credentials blob the caller must persist. Zeroized on drop.
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
    pub fn fingerprint_hex(&self) -> [u8; 16] {
        fingerprint_hex(self.fingerprint)
    }

    /// Deactivate the account at the CA.
    ///
    /// # Errors
    /// `AcmeError::Protocol`, `AcmeError::Transport`.
    pub async fn deactivate(self) -> Result<(), AcmeError> {
        let account = match self.inner {
            Some(account) => account,
            None => {
                let envelope: CredentialsEnvelope = serde_json::from_slice(&self.credentials_json)
                    .map_err(|_| AcmeError::Credentials)?;
                let directory_bytes = Bytes::from(
                    serde_json::to_vec(&envelope.directory)
                        .map_err(|_| AcmeError::Credentials)?,
                );
                let client = HttpClientImpl::new()
                    .await?
                    .with_directory_cache(envelope.directory_url, directory_bytes);
                Account::builder_with_http(Box::new(client))
                    .from_credentials(envelope.credentials)
                    .await
                    .map_err(map_account_error)?
            }
        };

        account.deactivate().await.map_err(map_account_error)
    }
}

/// Directory JSON structure, mirroring `instant_acme` internals.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
    #[serde(rename = "renewalInfo", default)]
    renewal_info: Option<String>,
    #[serde(default)]
    meta: Meta,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Meta {
    #[serde(default)]
    profiles: HashMap<String, String>,
}

/// Credentials stored by the caller.
#[derive(Serialize, Deserialize)]
struct CredentialsEnvelope {
    credentials: AccountCredentials,
    directory: Directory,
    directory_url: String,
    account_url: String,
}

/// HTTP client that can replay a cached directory response.
#[derive(Clone)]
struct HttpClientImpl {
    inner: HyperClient<HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>,
    directory_cache: Option<(String, Bytes)>,
}

impl HttpClientImpl {
    async fn new() -> Result<Self, AcmeError> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|e| AcmeError::Transport(e.to_string().into_boxed_str()))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let inner = HyperClient::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            inner,
            directory_cache: None,
        })
    }

    fn with_directory_cache(mut self, url: String, bytes: Bytes) -> Self {
        self.directory_cache = Some((url, bytes));
        self
    }
}

impl HttpClient for HttpClientImpl {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let inner = self.inner.clone();
        let cache = self.directory_cache.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            if parts.method == Method::GET {
                if let Some((url, bytes)) = &cache {
                    if parts.uri.to_string() == *url {
                        let response = Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(BodyWrapper::from(bytes.to_vec()))
                            .map_err(instant_acme::Error::Http)?;
                        return Ok(BytesResponse::from(response));
                    }
                }
            }
            let req = Request::from_parts(parts, body);
            let response = inner
                .request(req)
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            Ok(BytesResponse::from(response))
        })
    }
}

/// HTTP client wrapper that captures `Retry-After` on 429 responses.
struct RateLimitClient {
    inner: HttpClientImpl,
    retry_after: Arc<AtomicU64>,
}

impl RateLimitClient {
    fn new(inner: HttpClientImpl) -> Self {
        Self {
            inner,
            retry_after: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }
}

impl HttpClient for RateLimitClient {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let inner = self.inner.clone();
        let retry_after = self.retry_after.clone();
        Box::pin(async move {
            let response = inner.request(req).await?;
            if response.parts.status == StatusCode::TOO_MANY_REQUESTS {
                let secs = response
                    .parts
                    .headers
                    .get(http::header::RETRY_AFTER)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                let marker = match secs {
                    Some(secs) => {
                        retry_after.store(secs, Ordering::SeqCst);
                        format!("rateLimited:{secs}")
                    }
                    None => "rateLimited:none".to_owned(),
                };
                return Err(instant_acme::Error::Other(marker.into()));
            }
            Ok(response)
        })
    }
}

/// Parse directory bytes.
fn parse_directory(bytes: &[u8]) -> Result<Directory, AcmeError> {
    serde_json::from_slice(bytes).map_err(|e| AcmeError::Protocol {
        kind: "malformed-directory".into(),
        detail: sanitize_detail(&e.to_string()),
    })
}

/// Convert a non-2xx HTTP response into a protocol error.
fn protocol_error_from_response(bytes: &[u8], status: StatusCode) -> AcmeError {
    let problem: Option<instant_acme::Problem> = serde_json::from_slice(bytes).ok();
    let kind = problem
        .as_ref()
        .and_then(|p| p.r#type.as_deref())
        .unwrap_or("unknown");
    let detail = problem
        .as_ref()
        .and_then(|p| p.detail.as_deref())
        .unwrap_or_else(|| std::str::from_utf8(bytes).unwrap_or("unknown error"));
    AcmeError::Protocol {
        kind: kind.into(),
        detail: sanitize_detail(detail),
    }
}

/// Sanitize CA-controlled detail text.
fn sanitize_detail(input: &str) -> Box<str> {
    let filtered: String = input.chars().filter(|c| !c.is_control()).collect();
    let mut out = String::with_capacity(512);
    let mut len = 0usize;
    for ch in filtered.chars() {
        let char_len = ch.len_utf8();
        if len + char_len > 512 {
            break;
        }
        out.push(ch);
        len += char_len;
    }
    out.into_boxed_str()
}

/// Try to map a synthetic rate-limited error from [`RateLimitClient`].
fn try_rate_limited(err: &instant_acme::Error) -> Option<AcmeError> {
    let instant_acme::Error::Other(e) = err else {
        return None;
    };
    let s = e.to_string();
    if s == "rateLimited:none" {
        return Some(AcmeError::RateLimited { retry_after: None });
    }
    s.strip_prefix("rateLimited:")
        .and_then(|rest| rest.parse::<u32>().ok())
        .map(|secs| AcmeError::RateLimited {
            retry_after: Some(secs),
        })
}

/// Map directory-fetch errors.
fn map_directory_error(err: instant_acme::Error) -> AcmeError {
    match err {
        instant_acme::Error::Http(_)
        | instant_acme::Error::Hyper(_)
        | instant_acme::Error::InvalidUri(_) => AcmeError::Transport(err.to_string().into_boxed_str()),
        _ => AcmeError::Protocol {
            kind: "unknown".into(),
            detail: sanitize_detail(&err.to_string()),
        },
    }
}

/// Map account-creation errors.
fn map_create_error(err: instant_acme::Error, retry_after: Arc<AtomicU64>) -> AcmeError {
    if let Some(e) = try_rate_limited(&err) {
        return e;
    }

    match err {
        instant_acme::Error::Api(problem) => {
            let kind = problem.r#type.as_deref().unwrap_or("unknown");
            if kind == "urn:ietf:params:acme:error:externalAccountRequired" {
                return AcmeError::EabRequired;
            }
            if kind == "urn:ietf:params:acme:error:rateLimited" {
                let secs = retry_after.load(Ordering::SeqCst);
                return AcmeError::RateLimited {
                    retry_after: if secs == u64::MAX {
                        None
                    } else {
                        u32::try_from(secs).ok()
                    },
                };
            }
            AcmeError::Protocol {
                kind: kind.into(),
                detail: sanitize_detail(problem.detail.as_deref().unwrap_or("")),
            }
        }
        instant_acme::Error::Http(_)
        | instant_acme::Error::Hyper(_)
        | instant_acme::Error::InvalidUri(_) => {
            AcmeError::Transport(err.to_string().into_boxed_str())
        }
        _ => AcmeError::Protocol {
            kind: "unknown".into(),
            detail: sanitize_detail(&err.to_string()),
        },
    }
}

/// Map account-operation errors (deactivate, etc.).
fn map_account_error(err: instant_acme::Error) -> AcmeError {
    match err {
        instant_acme::Error::Api(problem) => AcmeError::Protocol {
            kind: problem.r#type.as_deref().unwrap_or("unknown").into(),
            detail: sanitize_detail(problem.detail.as_deref().unwrap_or("")),
        },
        instant_acme::Error::Http(_)
        | instant_acme::Error::Hyper(_)
        | instant_acme::Error::InvalidUri(_) => {
            AcmeError::Transport(err.to_string().into_boxed_str())
        }
        _ => AcmeError::Protocol {
            kind: "unknown".into(),
            detail: sanitize_detail(&err.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use super::*;
    use crate::AcmeConfig;

    fn ensure_provider() {
        let _ = irontraffic_tls::install_process_provider();
    }

    fn config(directory_url: &str) -> AcmeConfig {
        AcmeConfig {
            directory_url: directory_url.to_owned(),
            contacts: Vec::new(),
            terms_of_service_agreed: false,
            external_account_binding: None,
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: true,
        }
    }

    fn config_with_eab(directory_url: &str) -> AcmeConfig {
        AcmeConfig {
            directory_url: directory_url.to_owned(),
            contacts: Vec::new(),
            terms_of_service_agreed: true,
            external_account_binding: Some(EabConfig {
                kid: "test-account".to_owned(),
                hmac_key: "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W".to_owned(),
            }),
            profile: None,
            directory_ttl_secs: 86_400,
            allow_insecure_directory: true,
        }
    }

    fn start_server<F>(handler: F) -> (String, thread::JoinHandle<()>)
    where
        F: Fn(&str, &str, &[u8]) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16_384];
            loop {
                let n = match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let mut lines = req.lines();
                let first = lines.next().unwrap_or("");
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(req.len());
                let content_length = req
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.parse::<usize>().ok());
                let mut body = req[body_start..].as_bytes().to_vec();
                if let Some(cl) = content_length {
                    while body.len() < cl && body.len() < 16_384 {
                        let mut extra = [0u8; 4_096];
                        let n2 = stream.read(&mut extra).unwrap_or(0);
                        if n2 == 0 {
                            break;
                        }
                        body.extend_from_slice(&extra[..n2]);
                    }
                }
                let response = handler(method, path, &body);
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });
        (base_url, handle)
    }

    fn directory_json(base_url: &str, profiles: Option<&[(&str, &str)]>, ari: bool) -> String {
        let mut json = format!(
            "{{\"newNonce\":\"{base_url}/new-nonce\",\"newAccount\":\"{base_url}/new-account\",\"newOrder\":\"{base_url}/new-order\","
        );
        if ari {
            json.push_str(&format!("\"renewalInfo\":\"{base_url}/renewal-info\","));
        }
        if let Some(profiles) = profiles {
            json.push_str("\"meta\":{\"profiles\":{");
            for (i, (name, desc)) in profiles.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!("\"{name}\":\"{desc}\""));
            }
            json.push_str("}}");
        } else {
            json.push_str("\"meta\":{}");
        }
        json.push('}');
        json
    }

    fn problem_response(status: &str, problem_type: &str, detail: &str) -> String {
        let body = format!(
            "{{\"type\":\"{problem_type}\",\"detail\":\"{detail}\",\"status\":{status}}}"
        );
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/problem+json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn acme_terms_not_agreed() {
        let cfg = config("http://127.0.0.1:14000/dir");
        let dir = AcmeDirectory {
            directory_url: cfg.directory_url.clone().into_boxed_str(),
            directory_bytes: Bytes::new(),
            fetched_at: UnixSeconds::new(0),
            ttl_secs: 86_400,
            profiles: Box::new([]),
            has_renewal_info: false,
        };
        let err = AcmeAccount::create(&dir, &cfg).await.unwrap_err();
        assert_eq!(err, AcmeError::TermsNotAgreed);
    }

    #[tokio::test]
    async fn acme_eab_required_message() {
        ensure_provider();
        let (base_url, _handle) = start_server(|method, path, _body| {
            if method == "GET" && path == "/dir" {
                return format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    directory_json("", None, false).len(),
                    directory_json("", None, false)
                );
            }
            if method == "HEAD" && path == "/new-nonce" {
                return "HTTP/1.1 200 OK\r\nReplay-Nonce: nonce1\r\nConnection: close\r\n\r\n".to_owned();
            }
            if method == "POST" && path == "/new-account" {
                return problem_response(
                    "400 Bad Request",
                    "urn:ietf:params:acme:error:externalAccountRequired",
                    "EAB required",
                );
            }
            "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".to_owned()
        });
        let dir = AcmeDirectory::fetch(&config(&(base_url.clone() + "/dir")), UnixSeconds::new(0))
            .await
            .unwrap();
        let cfg = config(&(base_url + "/dir"));
        let err = AcmeAccount::create(&dir, &cfg).await.unwrap_err();
        assert_eq!(err, AcmeError::EabRequired);
        assert_eq!(
            err.to_string(),
            "this CA requires External Account Binding; \
             set acme.externalAccountBinding.kid and .hmacKey"
        );
    }

    #[tokio::test]
    async fn acme_unknown_profile_lists_available() {
        let (base_url, _handle) = start_server(|method, path, _body| {
            if method == "GET" && path == "/dir" {
                let json = directory_json(
                    "",
                    Some(&[("classic", "Classic"), ("shortlived", "Short-lived")]),
                    true,
                );
                return format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
            }
            "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".to_owned()
        });
        let mut cfg = config(&(base_url.clone() + "/dir"));
        cfg.profile = Some("tlsserver".to_owned());
        let err = AcmeDirectory::fetch(&cfg, UnixSeconds::new(0)).await.unwrap_err();
        assert!(matches!(err, AcmeError::UnknownProfile { .. }));
        let msg = err.to_string();
        assert!(msg.contains("tlsserver"));
        assert!(msg.contains("classic"));
        assert!(msg.contains("shortlived"));
    }

    #[tokio::test]
    async fn acme_profile_passthrough_when_none_advertised() {
        let (base_url, _handle) = start_server(|method, path, _body| {
            if method == "GET" && path == "/dir" {
                let json = directory_json("", None, false);
                return format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
            }
            "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".to_owned()
        });
        let mut cfg = config(&(base_url.clone() + "/dir"));
        cfg.profile = Some("anything".to_owned());
        let dir = AcmeDirectory::fetch(&cfg, UnixSeconds::new(0)).await.unwrap();
        assert!(!dir.is_stale(UnixSeconds::new(0)));
    }

    #[tokio::test]
    async fn acme_rate_limited_carries_retry_after() {
        ensure_provider();
        let (base_url, _handle) = start_server(|method, path, _body| {
            if method == "GET" && path == "/dir" {
                let json = directory_json("", None, false);
                return format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
            }
            if method == "HEAD" && path == "/new-nonce" {
                return "HTTP/1.1 200 OK\r\nReplay-Nonce: nonce1\r\nConnection: close\r\n\r\n".to_owned();
            }
            if method == "POST" && path == "/new-account" {
                let body = "{\"type\":\"urn:ietf:params:acme:error:rateLimited\",\"detail\":\"too many requests\",\"status\":429}";
                return format!(
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Type: application/problem+json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
            "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".to_owned()
        });
        let dir = AcmeDirectory::fetch(&config(&(base_url.clone() + "/dir")), UnixSeconds::new(0))
            .await
            .unwrap();
        let mut cfg = config(&(base_url + "/dir"));
        cfg.terms_of_service_agreed = true;
        let err = AcmeAccount::create(&dir, &cfg).await.unwrap_err();
        assert!(matches!(err, AcmeError::RateLimited { retry_after: Some(120) }));
    }

    #[tokio::test]
    async fn acme_detail_truncated_and_sanitized() {
        ensure_provider();
        let long_detail = "a\n".repeat(600);
        let detail_for_json = long_detail.replace('"', "\\\"");
        let (base_url, _handle) = {
            let detail_for_json = detail_for_json.clone();
            start_server(move |method, path, _body| {
                if method == "GET" && path == "/dir" {
                    let json = directory_json("", None, false);
                    return format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        json.len(),
                        json
                    );
                }
                if method == "HEAD" && path == "/new-nonce" {
                    return "HTTP/1.1 200 OK\r\nReplay-Nonce: nonce1\r\nConnection: close\r\n\r\n".to_owned();
                }
                if method == "POST" && path == "/new-account" {
                    let body = format!(
                        "{{\"type\":\"urn:ietf:params:acme:error:malformed\",\"detail\":\"{detail_for_json}\",\"status\":400}}"
                    );
                    return format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/problem+json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                }
                "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".to_owned()
            })
        };
        let dir = AcmeDirectory::fetch(&config(&(base_url.clone() + "/dir")), UnixSeconds::new(0))
            .await
            .unwrap();
        let mut cfg = config(&(base_url + "/dir"));
        cfg.terms_of_service_agreed = true;
        let err = AcmeAccount::create(&dir, &cfg).await.unwrap_err();
        let AcmeError::Protocol { detail, .. } = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(detail.as_bytes().len() <= 512);
        assert!(!detail.contains('\n'));
    }

    #[tokio::test]
    async fn acme_load_makes_no_network_call() {
        let blob = b"not-a-valid-envelope";
        let err = AcmeAccount::load(blob).unwrap_err();
        assert_eq!(err, AcmeError::Credentials);
    }

    #[tokio::test]
    async fn acme_load_truncated_blob() {
        let blob = b"{\"credentials\":";
        let err = AcmeAccount::load(blob).unwrap_err();
        assert_eq!(err, AcmeError::Credentials);
    }

    #[tokio::test]
    async fn acme_debug_hides_secrets() {
        ensure_provider();
        let (base_url, _handle) = start_server(|method, path, _body| {
            if method == "GET" && path == "/dir" {
                let json = directory_json("", None, false);
                return format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
            }
            if method == "HEAD" && path == "/new-nonce" {
                return "HTTP/1.1 200 OK\r\nReplay-Nonce: nonce1\r\nConnection: close\r\n\r\n".to_owned();
            }
            if method == "POST" && path == "/new-account" {
                return "HTTP/1.1 201 Created\r\nLocation: http://127.0.0.1:1/account/1\r\nConnection: close\r\n\r\n".to_owned();
            }
            "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".to_owned()
        });
        let dir = AcmeDirectory::fetch(&config(&(base_url.clone() + "/dir")), UnixSeconds::new(0))
            .await
            .unwrap();
        let cfg = config_with_eab(&(base_url + "/dir"));
        let account = AcmeAccount::create(&dir, &cfg).await.unwrap();
        let debug = format!("{:?}", account);
        assert!(!debug.contains(&cfg.external_account_binding.as_ref().unwrap().hmac_key));
        assert!(!debug.contains("privateKey"));
        let eab_debug = format!("{:?}", cfg.external_account_binding.as_ref().unwrap());
        assert!(!eab_debug.contains(&cfg.external_account_binding.as_ref().unwrap().hmac_key));
    }
}
