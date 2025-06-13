// src/validator.rs

use crate::client::JwksClient;
use crate::config::Config;
use crate::error::NilaOidcError;
use jsonwebtoken::{decode, decode_header, Validation, TokenData};
use serde::Deserialize;
use std::collections::HashSet;
use tracing::instrument;

/// The main OIDC ID Token validator.
///
/// This struct is initialized with a `Config` and should be created once
/// and reused for all validation requests. It manages the JWKS client
/// and performs all necessary validation steps.
#[derive(Clone)]
pub struct Validator {
    config: Config,
    jwks_client: JwksClient,
}

/// The claims decoded from a valid ID Token.
///
/// This struct contains the standard OIDC claims. Custom claims can be
/// included by adding them to this struct and implementing `serde::Deserialize`.

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub nonce: Option<String>,
    // Add other custom claims here if needed.
}

impl Validator {
    /// Creates a new `Validator` with the given configuration.
    pub fn new(config: Config) -> Self {
        let jwks_client = JwksClient::new(config.clone());
        Self { config, jwks_client }
    }

    /// Validates an OIDC ID Token.
    ///
    /// This method performs a full validation of the token, including:
    /// 1. Signature verification against the provider's JWKS.
    /// 2. Validation of standard claims (`iss`, `aud`, `exp`, `iat`).
    /// 3. Nonce validation (if enabled in config).
    ///
    /// # Arguments
    ///
    /// * `token` - The raw ID Token string.
    /// * `nonce` - An optional nonce to validate against the token's `nonce` claim.
    ///             This is required if `config.validation.validate_nonce` is `true`.
    ///
    /// # Returns
    ///
    /// A `TokenData<Claims>` object containing the decoded claims if validation is successful.
    #[instrument(skip(self, token), err)]
    pub async fn validate(&self, token: &str, nonce: Option<&str>) -> Result<TokenData<Claims>, NilaOidcError> {
        // 1. Decode header to get kid and alg without validation.
        let header = decode_header(token).map_err(|e| NilaOidcError::JwtError(e.into()))?;
        
        // 2. Check if the algorithm is allowed.
        if!self.config.validation.algorithms.contains(&header.alg) {
            return Err(NilaOidcError::UnsupportedAlgorithm(header.alg));
        }

        // 3. Get the key from the JWKS client.
        let kid = header.kid.ok_or(NilaOidcError::MissingKeyId)?;
        let decoding_key = self.jwks_client.get_key(&kid).await?;

        // 4. Construct validation options.
        let mut validation = Validation::new(header.alg);
        validation.leeway = self.config.validation.leeway.as_secs();
        validation.set_issuer(&[self.config.issuer_url.as_str()]);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);

        // 5. Decode and validate the token.
        let token_data = decode::<Claims>(token, &decoding_key, &validation)
           .map_err(|e| NilaOidcError::JwtError(e.into()))?;

        // 6. Validate the nonce if required.
        if self.config.validation.validate_nonce {
            let expected_nonce = nonce.ok_or(NilaOidcError::MissingNonce)?;
            let token_nonce = token_data.claims.nonce.as_deref().ok_or(NilaOidcError::MissingNonce)?;
            if expected_nonce!= token_nonce {
                return Err(NilaOidcError::NonceMismatch);
            }
        }

        Ok(token_data)
    }
}