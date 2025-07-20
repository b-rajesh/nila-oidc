use crate::error::NilaOidcError;
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use sha2::{Digest, Sha256};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use url::Url;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use rsa::traits::PublicKeyParts;
use rsa::pkcs1::EncodeRsaPrivateKey;
/// Details for a client that is allowed to request tokens.
#[derive(Deserialize, Clone, Debug)]
pub struct ClientDetails {
    /// The client secret. Required unless the client is marked as public.
    pub client_secret: Option<String>,
    /// A space-separated string of scopes the client is allowed to request. Must be a subset of the OP's `supported_scopes`.
    pub allowed_scopes: Option<String>,
    /// A space-separated string of default scopes to grant if none are requested.
    pub default_scopes: Option<String>,
}

/// Defines the source for the JWT signing key.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "value")] // Use adjacent tagging for clarity and robustness
#[serde(rename_all = "snake_case")] // This still applies to the 'type' tag value (e.g., "shared_secret")
pub enum SigningKeyConfig {
    /// A shared secret for symmetric algorithms (e.g., HS256).
    SharedSecret(String),
    /// Path to a PEM-encoded RSA private key file.
    RsaPemFile(PathBuf),
}

/// Configuration for the JWT token generator.
#[derive(Deserialize, Clone, Debug)]
pub struct GeneratorConfig {
    /// The issuer URL to be placed in the `iss` claim of generated tokens.
    pub issuer: Url,
    /// The algorithm to use for signing the token.
    pub algorithm: Algorithm,
    /// A map of client IDs to their details.
    pub clients: HashMap<String, ClientDetails>,
    /// The time-to-live for generated tokens, in seconds.
    pub token_ttl_seconds: u64,
    /// The key material used for signing tokens.
    pub signing_key: SigningKeyConfig,
    /// A space-separated list of all scopes this provider supports.
    pub supported_scopes: Option<String>,
    /// The mandatory custom grant type URI for the public client flow.
    pub identity_nila_grant_type_extension: String,
}

/// A JWT token generator for the OAuth2 Client Credentials Grant.
#[derive(Clone)]
pub struct Generator {
    pub config: GeneratorConfig,
    encoding_key: EncodingKey,
    public_jwk: Option<serde_json::Value>, // Stores the public key in JWK format if using an asymmetric key
}

/// Claims for the generated access token.
#[derive(Debug, Serialize)]
struct AccessTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    jti: String,
    aud: &'a str, // Audience can be the same as issuer or a specific resource server
    exp: u64,
    iat: u64,
    gty: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

impl Generator {
    /// Creates a new `Generator` with the given configuration.
    ///
    /// This function also validates the configuration to ensure that all configured
    /// per-client scopes (`allowed_scopes` and `default_scopes`) are valid
    /// according to the globally `supported_scopes`.
    pub fn new(config: GeneratorConfig) -> Result<Self, NilaOidcError> {
        // --- Validate Scope Configuration at Startup ---
        if let Some(supported_scopes_str) = &config.supported_scopes {
            let supported: std::collections::HashSet<&str> = supported_scopes_str.split_whitespace().collect();
            for (client_id, details) in &config.clients {
                if let Some(allowed_scopes_str) = &details.allowed_scopes {
                    let allowed: std::collections::HashSet<&str> = allowed_scopes_str.split_whitespace().collect();
                    if !allowed.is_subset(&supported) {
                        return Err(NilaOidcError::InvalidScope(format!("Client '{}' is configured with allowed_scopes that are not in the supported_scopes list.", client_id)));
                    }
                }
                if let Some(default_scopes_str) = &details.default_scopes {
                     let default: std::collections::HashSet<&str> = default_scopes_str.split_whitespace().collect();
                     if !default.is_subset(&supported) {
                        return Err(NilaOidcError::InvalidScope(format!("Client '{}' is configured with default_scopes that are not in the supported_scopes list.", client_id)));
                    }
                }
            }
        }

        let (encoding_key, public_jwk) = match &config.signing_key {
            SigningKeyConfig::SharedSecret(secret) => {
                (EncodingKey::from_secret(secret.as_bytes()), None)
            }
            SigningKeyConfig::RsaPemFile(path) => {
                // Read the PEM file content. This is more robust than embedding in YAML.
                let pem = std::fs::read_to_string(path).map_err(|e| {
                    NilaOidcError::InvalidKeyFormat(format!(
                        "Failed to read RSA private key file from {:?}: {}", path, e
                    ))
                })?;

                // First, parse the PKCS#8 PEM into an RsaPrivateKey. We need this for both
                // creating the encoding key and for extracting the public key components for the JWKS.
                let private_key = RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|e| {
                    NilaOidcError::InvalidKeyFormat(format!(
                        "Failed to parse RSA private key from PKCS#8 PEM: {}",
                        e
                    ))
                })?;

                // The `jsonwebtoken` crate's `from_pkcs8_pem` can be problematic due to complex trait bounds.
                // A more robust method is to parse the key ourselves (as above) and then
                // convert it to a format that `jsonwebtoken` can reliably handle, like PKCS#1 DER.
                let pkcs1_der = private_key.to_pkcs1_der().map_err(|e| {
                    NilaOidcError::InvalidKeyFormat(format!(
                        "Failed to convert RSA key to PKCS#1 DER: {}", e
                    ))
                })?;
                let key = EncodingKey::from_rsa_der(pkcs1_der.as_bytes());
                let public_key = private_key.to_public_key();

                // Extract n (modulus) and e (exponent) and base64url-encode them.
                let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
                let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

                // --- Production-Grade `kid` Generation (JWK Thumbprint - RFC 7638) ---
                // 1. Create a canonical JSON representation of the key's required members.
                let canonical_jwk = json!({
                    "e": e,
                    "kty": "RSA",
                    "n": n,
                });
                // The unwrap is safe here as serialization of this static structure cannot fail.
                let canonical_jwk_string = serde_json::to_string(&canonical_jwk).unwrap();

                // 2. Compute the SHA-256 hash of the canonical representation.
                let mut hasher = Sha256::new();
                hasher.update(canonical_jwk_string.as_bytes());
                let hash_result = hasher.finalize();

                // 3. Base64URL-encode the hash to create the final `kid`.
                let kid = URL_SAFE_NO_PAD.encode(hash_result);

                let jwk = json!({
                    "kty": "RSA",
                    "n": n,
                    "e": e,
                    "alg": format!("{:?}", config.algorithm),
                    "use": "sig",
                    "kid": kid,
                });

                (key, Some(jwk))
            }
        };

        Ok(Self { config, encoding_key, public_jwk })
    }

    /// Issues a new JWT access token after validating client credentials.
    pub fn issue_token(
        &self,
        client_id: &str,
        client_secret: &str,
        grant_type: &str,
        scope: Option<&str>,
    ) -> Result<String, NilaOidcError> {
        tracing::debug!(client_id = %client_id, "Attempting to issue token.");

        let client_details = self
            .config
            .clients
            .get(client_id)
            .ok_or_else(|| {
                tracing::warn!(client_id = %client_id, "Client ID not found in configuration.");
                NilaOidcError::InvalidClientCredentials
            })?;

        // Validate credentials based on the grant type.
        match grant_type {
            "client_credentials" => {
                // This grant type requires a client secret that must match the configured one.
                if client_details.client_secret.as_deref() != Some(client_secret) {
                    tracing::warn!(client_id = %client_id, "Client secret mismatch or not provided for 'client_credentials' grant.");
                    return Err(NilaOidcError::InvalidClientCredentials);
                }
            }
            g if g == self.config.identity_nila_grant_type_extension => {
                // For the public grant type, we only validate that the client_id exists.
                // No secret check is performed.
            }
            unsupported_grant => {
                return Err(NilaOidcError::UnsupportedGrantType(unsupported_grant.to_string()));
            }
        }

        tracing::debug!(client_id = %client_id, "Client credentials validated successfully.");

        // --- Scope Validation ---
        let final_scope = match scope {
            Some(requested_scope_str) => {
                // If scopes are requested, they must be validated against the client's allowed scopes.
                let allowed: std::collections::HashSet<&str> = client_details.allowed_scopes.as_deref().unwrap_or("").split_whitespace().collect();
                let requested: std::collections::HashSet<&str> = requested_scope_str.split_whitespace().collect();

                if requested.is_empty() {
                    // If the requested scope string is present but empty, use default scopes.
                    client_details.default_scopes.as_deref()
                } else if requested.is_subset(&allowed) {
                    // All requested scopes are allowed.
                    Some(requested_scope_str)
                } else {
                    // At least one requested scope is not allowed.
                    let invalid_scopes: Vec<&&str> = requested.difference(&allowed).collect();
                    tracing::warn!(client_id = %client_id, "Client requested invalid scopes: {:?}", invalid_scopes);
                    return Err(NilaOidcError::InvalidScope(format!("The following scopes are not permitted for this client: {:?}", invalid_scopes)));
                }
            }
            None => {
                // No scopes were requested, so grant the default scopes.
                client_details.default_scopes.as_deref()
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = AccessTokenClaims {
            iss: self.config.issuer.as_str(),
            sub: client_id,
            jti: Uuid::new_v4().to_string(),
            aud: client_id,
            iat: now,
            exp: now + self.config.token_ttl_seconds,
            gty: grant_type,
            scope: final_scope,
        };

        // Create the header and include the kid if it's an asymmetric key
        let mut header = Header::new(self.config.algorithm);
        if let Some(ref jwk) = self.public_jwk {
            if let Some(kid) = jwk.get("kid").and_then(|k| k.as_str()) {
                tracing::debug!(kid = %kid, "Adding kid to JWT header.");
                header.kid = Some(kid.to_string());
            } else {
                tracing::warn!("Could not find 'kid' in public_jwk; token will be generated without it.");
            }
        }

         encode(
             &header,
             &claims,
             &self.encoding_key,
         )
         .map_err(|e| NilaOidcError::TokenGenerationError(e.to_string()))
    }

    /// Returns the public JWKS for the signing key, if one is available (e.g., for RSA).
    /// This method is intended to be called by an external service (like a web server)
    /// to expose the JWKS endpoint.
    pub fn get_public_jwks(&self) -> Option<serde_json::Value> {
        self.public_jwk.as_ref().map(|jwk| {
            json!({ "keys": [jwk] })
        })
    }
}
