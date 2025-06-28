// src/model.rs

use serde::Deserialize;

/// Represents the data structure of an OIDC provider's discovery document.
/// Found at the `.well-known/openid-configuration` endpoint.

#[derive(Debug, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
}

/// Represents a single JSON Web Key (JWK) as defined in RFC 7517.

#[derive(Debug, Deserialize)]
pub struct JsonWebKey {
    pub kid: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub use_purpose: Option<String>,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
}

/// Represents a JSON Web Key Set (JWKS), which is a collection of JWKs.

#[derive(Debug, Deserialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}