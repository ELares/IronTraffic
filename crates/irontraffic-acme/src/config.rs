// SPDX-License-Identifier: MIT OR Apache-2.0

//! ACME configuration.

use crate::account::AcmeError;

/// ACME configuration for one CA account.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AcmeConfig {
    /// Directory URL.
    pub directory_url: String,
}

impl AcmeConfig {
    /// Validate.
    pub fn validate(&self) -> Result<(), AcmeError> {
        let _ = self;
        Ok(())
    }
}
