// src/validator.rs

use crate::client::JwksClient;
use crate::config::{Config, KeySourceConfig};
use crate::error::NilaOidcError;
use jsonwebtoken::{decode, decode_header, TokenData, Validation};
use serde::de::DeserializeOwned; // Import DeserializeOwned
use tracing::instrument;
use serde::Deserialize;
use jsonwebtoken::DecodingKey;
/// The main OIDC ID Token validator.
/// Trait for claims types that include a nonce.
pub trait HasNonce {
    /// Returns the nonce claim, if present.
    fn get_nonce(&self) -> Option<&str>;
}
///
/// This struct is initialized with a `Config` and should be created once
/// and reused for all validation requests. It manages the JWKS client
/// and performs all necessary validation steps.
#[derive(Clone)]
pub struct Validator {
    config: Config,
    // JwksClient is only present if config.key_source is Jwks
    jwks_client: Option<JwksClient>,
}

/// The claims decoded from a valid ID Token.
///
/// This struct contains the standard OIDC claims. Custom claims can be
/// included by creating a new struct that implements `serde::Deserialize` and `HasNonce`.
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

// Implement HasNonce for the standard Claims struct.
impl HasNonce for Claims {
    fn get_nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }
}

impl Validator {
    /// Creates a new `Validator` with the given configuration.
    pub fn new(config: Config) -> Self {
        let jwks_client = match &config.key_source {
            KeySourceConfig::Jwks { jwks_uri, cache_ttl } => {
                Some(JwksClient::new(
                    config.issuer_url.clone(), // Needed for discovery if jwks_uri is None
                    jwks_uri.clone(),
                    *cache_ttl
                ))
            }
            KeySourceConfig::SharedSecret(_) => None,
        };
        Self { config, jwks_client}
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
    /// A `TokenData` object containing the decoded claims if validation is successful.
    #[instrument(skip(self, token), err)]
    pub async fn validate<T: DeserializeOwned + HasNonce>(
        &self,
        token: &str,
        nonce_to_verify: Option<&str>,
    ) -> Result<TokenData<T>, NilaOidcError> {
        // 1. Decode header to get kid and alg without validation.
        let header = decode_header(token).map_err(NilaOidcError::JwtValidation)?;

        // 2. Check if the algorithm is allowed.
        if !self.config.validation.algorithms.contains(&header.alg) {
            return Err(NilaOidcError::UnsupportedAlgorithm(header.alg));
        }

        // 3. Get the decoding key based on algorithm type and configuration.
        let decoding_key = match header.alg {
            jsonwebtoken::Algorithm::HS256 | jsonwebtoken::Algorithm::HS384 | jsonwebtoken::Algorithm::HS512 => {
                // Symmetric algorithm, requires a shared secret
                match &self.config.key_source {
                    KeySourceConfig::SharedSecret(secret) => DecodingKey::from_secret(secret.as_slice()),
                    KeySourceConfig::Jwks { .. } => return Err(NilaOidcError::UnsupportedKeyTypeForAlgorithm), // JWKS configured for symmetric alg
                }
            }
            _ => { // Asymmetric algorithm, requires JWKS
                match &self.config.key_source {
                    KeySourceConfig::Jwks { .. } => {
                        let jwks_client = self.jwks_client.as_ref().ok_or(NilaOidcError::MissingKeyMaterial)?; // Should not happen if config is Jwks
                        let kid = header.kid.ok_or(NilaOidcError::MissingKeyId)?;
                        (*jwks_client.get_key(&kid).await?).clone() // Clone the DecodingKey from the Arc
                    }
                    KeySourceConfig::SharedSecret(_) => return Err(NilaOidcError::UnsupportedKeyTypeForAlgorithm), // Shared secret configured for asymmetric alg
                }
            }
        };


        // 4. Construct validation options.
        let mut validation = Validation::new(header.alg);
        validation.leeway = self.config.validation.leeway.as_secs();
        // issuer_url is not optional in Config, so we can use it directly.
        validation.set_issuer(&[self.config.issuer_url.as_str()]);
        validation.set_audience(&[&self.config.client_id]); // client_id is typically required as audience
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);

        // 5. Decode and validate the token.
        let token_data = decode::<T>(token, &decoding_key, &validation)
            .map_err(NilaOidcError::JwtValidation)?;

        // 6. Validate the nonce if required.
        if self.config.validation.validate_nonce {
            let expected_nonce_value = nonce_to_verify
                .ok_or(NilaOidcError::MissingNonceForValidation)?;

            // Use the HasNonce trait to get the nonce from the claims.
            let token_nonce_value = token_data.claims.get_nonce()
                .ok_or(NilaOidcError::MissingNonceInToken)?;

            if expected_nonce_value != token_nonce_value {
                return Err(NilaOidcError::NonceMismatch);
            }
        }

        Ok(token_data)
    }
}