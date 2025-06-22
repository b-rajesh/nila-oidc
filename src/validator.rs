// src/validator.rs

use crate::client::JwksClient;
use crate::config::{Config, KeySourceConfig};
use crate::error::NilaOidcError;
use jsonwebtoken::{decode, decode_header, TokenData, Validation};
use serde::de::DeserializeOwned; // Import DeserializeOwned
use tracing::{debug, instrument};
use serde::Deserialize; // Serialize is no longer needed on T for this
use jsonwebtoken::DecodingKey;
use serde::Serialize;
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
#[derive(Debug, Deserialize, Serialize)] // Serialize is still useful if users want to log/pass around the typed claims
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub nonce: Option<String>,
    // Standard Claims struct should remain minimal.
    // Users can define their own structs with custom claims if they need typed access.
    // For generic validation, we'll parse the raw payload.
    // Add other custom claims here if needed.
}

// Implement HasNonce for the standard Claims struct.
impl HasNonce for Claims {
    fn get_nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }
}

// Helper function to decode JWT payload segment
fn decode_raw_payload_to_value(token_str: &str) -> Result<serde_json::Value, NilaOidcError> {
    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() < 2 { // Need at least header and payload
        return Err(NilaOidcError::JwtValidation(jsonwebtoken::errors::ErrorKind::InvalidToken.into()));
    }
    let payload_segment = parts[1];
    let decoded_payload_bytes = base64_url::decode(payload_segment)
        .map_err(NilaOidcError::Base64DecodeError)?;
    
    serde_json::from_slice(&decoded_payload_bytes)
        .map_err(|_| NilaOidcError::JwtValidation(
            jsonwebtoken::errors::ErrorKind::InvalidToken.into()))
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
    pub async fn validate<T: DeserializeOwned + HasNonce>( // Removed Serialize bound from T
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

        // 7. Perform custom claim assertions if configured.
        // To do this generically, we'll serialize T to serde_json::Value.
        if self.config.validation.required_claims.is_some() || self.config.validation.exact_match_claims.is_some() {
            // Decode the raw payload to get all claims, regardless of T's structure
            let all_claims_in_token = decode_raw_payload_to_value(token)?;
            debug!("All claims in token for custom validation: {}", all_claims_in_token.to_string());

            if let Some(required_claims) = &self.config.validation.required_claims {
                for claim_name in required_claims {
                    debug!("Checking required claim: '{}', Value in token: {:?}", claim_name, all_claims_in_token.get(claim_name));
                    if all_claims_in_token.get(claim_name).is_none() || all_claims_in_token.get(claim_name).unwrap().is_null() {
                        debug!("Missing required claim: {}", claim_name);
                        return Err(NilaOidcError::MissingRequiredClaim(claim_name.clone()));
                    }
                }
            }

            if let Some(exact_match_claims) = &self.config.validation.exact_match_claims {
                for (claim_name, expected_value) in exact_match_claims {
                    match all_claims_in_token.get(claim_name) {
                        Some(actual_value) if actual_value == expected_value => {
                            // Value matches, continue
                        }
                        Some(actual_value) => {
                            debug!("Claim value mismatch for '{}'. Expected: {:?}, Actual: {:?}", claim_name, expected_value, actual_value);
                            return Err(NilaOidcError::ClaimValueMismatch { claim: claim_name.clone(), expected: expected_value.clone(), actual: actual_value.clone() });
                        }
                        None => { // Claim not present, but was it in required_claims? If not, this is effectively a mismatch if an exact value was expected.
                            debug!("Claim '{}' expected for exact match not found in token.", claim_name);
                            let mismatch_error = NilaOidcError::ClaimValueMismatch {
                                claim: claim_name.clone(),
                                expected: expected_value.clone(),
                                actual: serde_json::Value::Null
                            };
                            return Err(mismatch_error);
                        }
                    }
                }
            }
        }
        Ok(token_data)
    }
}