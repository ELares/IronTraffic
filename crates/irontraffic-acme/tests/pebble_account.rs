// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests against a Pebble ACME test server.
//!
//! Run with:
//!
//! ```text
//! cargo test -p irontraffic-acme --features acme-integration --test pebble_account
//! ```
//!
//! Requires a Pebble instance reachable at `PEBBLE_DIRECTORY_URL` (default
//! `https://localhost:14000/dir`).

#![cfg(feature = "acme-integration")]

use irontraffic_acme::account::{AcmeAccount, AcmeDirectory, AcmeError};
use irontraffic_acme::config::AcmeConfig;
use irontraffic_tls::time::UnixSeconds;
use std::sync::{LazyLock, Mutex};

/// The Pebble directory URL, overridable via env var.
fn pebble_directory_url() -> String {
    std::env::var("PEBBLE_DIRECTORY_URL")
        .unwrap_or_else(|_| "https://localhost:14000/dir".to_owned())
}

/// Build a minimal `AcmeConfig` for Pebble.
fn pebble_config() -> AcmeConfig {
    AcmeConfig {
        directory_url: pebble_directory_url(),
        contacts: vec!["admin@example.com".to_owned()],
        terms_of_service_agreed: true,
        external_account_binding: None,
        profile: None,
        directory_ttl_secs: 86_400,
        allow_insecure_directory: true,
    }
}

/// A helper that ensures at most one integration test runs at a time.
fn serial() -> &'static Mutex<()> {
    static LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    &LOCK
}

/// Check if Pebble is reachable.
fn pebble_is_reachable() -> bool {
    let url = pebble_directory_url();
    let uri: http::Uri = match url.parse() {
        Ok(u) => u,
        Err(_) => return false,
    };
    let host = match uri.host() {
        Some(h) => h,
        None => return false,
    };
    let port = uri.port_u16().unwrap_or(443);
    let addr: std::net::SocketAddr = match format!("{host}:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)).is_ok()
}

#[tokio::test]
async fn pebble_create_and_load_account() {
    if !pebble_is_reachable() {
        return;
    }
    let _guard = serial().lock().unwrap_or_else(|e| e.into_inner());

    let cfg = pebble_config();
    let now = UnixSeconds::new(1_000_000);

    let dir = AcmeDirectory::fetch(&cfg, now)
        .await
        .expect("should fetch Pebble directory");

    let account = AcmeAccount::create(&dir, &cfg)
        .await
        .expect("should create account against Pebble");

    let url = account.url().to_owned();
    let creds = account.credentials_json().to_vec();

    drop(account);

    let loaded = AcmeAccount::load(&creds)
        .await
        .expect("should load from persisted credentials");

    assert_eq!(loaded.url(), url, "loaded account URL must match");

    loaded
        .deactivate()
        .await
        .expect("should deactivate account");
}

#[tokio::test]
async fn pebble_create_without_terms_fails() {
    if !pebble_is_reachable() {
        return;
    }
    let _guard = serial().lock().unwrap_or_else(|e| e.into_inner());

    let mut cfg = pebble_config();
    cfg.terms_of_service_agreed = false;

    let result = AcmeAccount::create(
        &AcmeDirectory::fetch(&pebble_config(), UnixSeconds::new(1_000_000))
            .await
            .expect("should fetch Pebble directory"),
        &cfg,
    )
    .await;

    assert!(matches!(result, Err(AcmeError::TermsNotAgreed)));
}

#[tokio::test]
async fn pebble_directory_reports_renewal_info() {
    if !pebble_is_reachable() {
        return;
    }
    let _guard = serial().lock().unwrap_or_else(|e| e.into_inner());

    let cfg = pebble_config();
    let now = UnixSeconds::new(1_000_000);

    let dir = AcmeDirectory::fetch(&cfg, now)
        .await
        .expect("should fetch Pebble directory");

    assert!(dir.has_renewal_info(), "Pebble implements ARI");
}

#[tokio::test]
async fn pebble_eab_required_path() {
    if !pebble_is_reachable() {
        return;
    }
    let _guard = serial().lock().unwrap_or_else(|e| e.into_inner());

    // For a Pebble that requires EAB: without EAB, we expect EabRequired.
    // With EAB, we expect success.
    let eab_required =
        std::env::var("PEBBLE_EAB_REQUIRED").unwrap_or_else(|_| "false".to_owned()) == "true";

    if eab_required {
        let cfg_no_eab = pebble_config();
        let dir = AcmeDirectory::fetch(&cfg_no_eab, UnixSeconds::new(1_000_000))
            .await
            .expect("should fetch Pebble directory");

        let result = AcmeAccount::create(&dir, &cfg_no_eab).await;
        assert!(matches!(result, Err(AcmeError::EabRequired)));

        // With EAB configured, the test must supply the EAB credentials via env vars.
        let eab_kid = std::env::var("PEBBLE_EAB_KID")
            .expect("PEBBLE_EAB_KID must be set when PEBBLE_EAB_REQUIRED=true");
        let eab_hmac = std::env::var("PEBBLE_EAB_HMAC_KEY")
            .expect("PEBBLE_EAB_HMAC_KEY must be set when PEBBLE_EAB_REQUIRED=true");

        let mut cfg_with_eab = pebble_config();
        cfg_with_eab.external_account_binding = Some(irontraffic_acme::config::EabConfig {
            kid: eab_kid,
            hmac_key: eab_hmac,
        });

        let account = AcmeAccount::create(&dir, &cfg_with_eab)
            .await
            .expect("should create account with EAB against Pebble");

        account
            .deactivate()
            .await
            .expect("should deactivate account");
    }
    // If EAB is not required by the Pebble instance, this test is a no-op.
}
