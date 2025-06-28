// src/validator/mod.rs

pub mod client;
pub mod config;
pub mod model;
use crate::error::NilaOidcError;
use client::JwksClient;
use config::{Config, KeySourceConfig};
use jsonwebtoken::{decode, decode_header, DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned; // Import DeserializeOwned
use tracing::{debug, instrument};
use serde::Deserialize; // Serialize is no longer needed on T for this

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
    pub aud: Option<String>,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub nonce: Option<String>,
    // Standard Claims struct should remain minimal.
    // Users can define their own structs with custom claims if they need typed access.
    // For generic validation, we'll parse the raw payload.
    // Add other custom claims here if needed.
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
    pub async fn validate<T: DeserializeOwned>(
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

        // --- Special Handling for Audience from `assert_claims` ---
        let mut audience_is_configured = false;
        if let Some(claims_to_assert) = &self.config.validation.assert_claims {
            if let Some(aud_value) = claims_to_assert.get("aud") {
                let audiences: Vec<String> = match aud_value {
                    serde_json::Value::String(s) => vec![s.clone()],
                    serde_json::Value::Array(arr) => arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect(),
                    _ => {
                        return Err(NilaOidcError::InvalidConfiguration(
                            "'aud' in assert_claims must be a string or an array of strings".to_string(),
                        ));
                    }
                };
                if !audiences.is_empty() {
                    validation.set_audience(&audiences);
                    audience_is_configured = true;
                }
            }
        }

        // This is the key change: Explicitly disable audience validation in the underlying
        // library if it has not been configured. Otherwise, the library's default
        // behavior will cause an `InvalidAudience` error if a token contains an `aud` claim.
        if !audience_is_configured {
            validation.validate_aud = false;
        }
        // The 'jsonwebtoken' crate automatically requires 'exp', 'iat', 'iss', 'sub'
        // if they are set in the validation struct. We only need to conditionally
        // require 'aud', and also respect any user-defined required claims.
        let mut required_claims: std::collections::HashSet<&str> =
            ["exp", "iat", "iss", "sub"].iter().cloned().collect();

        if audience_is_configured {
            required_claims.insert("aud");
        }

        // Add any user-defined required claims from the config.
        if let Some(user_required_claims) = &self.config.validation.required_claims {
            for claim in user_required_claims {
                required_claims.insert(claim);
            }
        }

        let final_required_claims: Vec<&str> = required_claims.into_iter().collect();
        validation.set_required_spec_claims(&final_required_claims);

        // 5. Decode the token into a generic serde_json::Value first. This performs
        // all standard JWT validation: signature, expiry, issuer, and (if configured) audience.
        let token_data_value = decode::<serde_json::Value>(token, &decoding_key, &validation)
            .map_err(NilaOidcError::JwtValidation)?;

        let all_claims_in_token = token_data_value.claims;

        // 6. Perform custom claim assertions if configured.
        if let Some(claims_to_assert) = &self.config.validation.assert_claims {
            for (claim_name, expected_value) in claims_to_assert {
                // Audience is already validated by the `decode` function, so we can skip it here.
                if claim_name == "aud" && audience_is_configured {
                    continue;
                }
                match all_claims_in_token.get(claim_name) {
                    Some(actual_value) if actual_value == expected_value => {
                        // Value matches, continue
                    }
                    Some(actual_value) => {
                        debug!("Claim value mismatch for '{}'. Expected: {:?}, Actual: {:?}", claim_name, expected_value, actual_value);
                        return Err(NilaOidcError::ClaimValueMismatch { claim: claim_name.clone(), expected: expected_value.clone(), actual: actual_value.clone() });
                    }
                    None => {
                        debug!("Claim '{}' expected for exact match not found in token.", claim_name);
                        return Err(NilaOidcError::ClaimValueMismatch {
                            claim: claim_name.clone(),
                            expected: expected_value.clone(),
                            actual: serde_json::Value::Null,
                        });
                    }
                }
            }
        }
        // 7. Validate the nonce if required.
        if self.config.validation.validate_nonce {
            let expected_nonce_value = nonce_to_verify.ok_or(NilaOidcError::MissingNonceForValidation)?;
            let token_nonce_value = all_claims_in_token.get("nonce").and_then(|v| v.as_str()).ok_or(NilaOidcError::MissingNonceInToken)?;
            if expected_nonce_value != token_nonce_value {
                return Err(NilaOidcError::NonceMismatch);
            }
        }
       // 8. If all validation passes, deserialize the generic Value into the user's target type T.
        let final_claims: T = serde_json::from_value(all_claims_in_token)
            .map_err(|e| NilaOidcError::ClaimDeserializationError(e.to_string()))?;

        Ok(TokenData { header: token_data_value.header, claims: final_claims })

    }
}