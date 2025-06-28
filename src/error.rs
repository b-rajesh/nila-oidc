// src/error.rs

use thiserror::Error;
use jsonwebtoken::Algorithm;
use base64::DecodeError;

/// The primary error type for the `nila-oidc` library.
#[derive(Debug, Error)]
pub enum NilaOidcError {
    /// Errors originating from the `jsonwebtoken` crate during token validation.
    #[error("JWT validation error: {0}")]
    JwtValidation(#[from] jsonwebtoken::errors::Error),

    /// An error occurred during an HTTP request.
    #[error("HTTP request error")]
    HttpError(#[from] reqwest::Error),

    /// A required configuration field is missing.
    #[error("A required configuration field is missing: {0}")]
    MissingConfiguration(String),

    /// A configuration value is invalid.
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// A provided URL could not be parsed.
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// The configuration for key sources is ambiguous (e.g., both JWKS and a shared secret were provided).
    #[error("Ambiguous key source configuration: {0}")]
    AmbiguousKeySource(String),

    /// The JWT header is missing the required 'kid' (Key ID) field.
    #[error("The JWT header is missing the 'kid' (Key ID) field")]
    MissingKeyId,

    /// A key with the specified 'kid' was not found in the JSON Web Key Set.
    #[error("Key not found for kid: {0}")]
    KeyNotFound(String),

    /// A cryptographic key (e.g., PEM, JWK) is malformed or invalid.
    /// This will now contain the detailed underlying parsing error.
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// The nonce in the token does not match the expected nonce.
    #[error("Nonce mismatch: the nonce in the token does not match the expected nonce")]
    NonceMismatch,

    /// A required claim is missing from the token.
    #[error("A required claim is missing from the token: {0}")]
    MissingRequiredClaim(String),

    /// A claim's value does not match the expected value.
    #[error("Claim '{claim}' value mismatch. Expected: {expected}, Actual: {actual}")]
    ClaimValueMismatch {
        claim: String,
        expected: serde_json::Value,
        actual: serde_json::Value,
    },

    /// An error occurred during the generation of a new token.
    #[error("Token generation failed: {0}")]
    TokenGenerationError(String),

    /// The provided client credentials (ID and/or secret) are invalid.
    #[error("Invalid client credentials: client not found or secret is incorrect")]
    InvalidClientCredentials,

    /// The algorithm specified in the JWT header is not supported by the configuration.
    #[error("Unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(Algorithm),

    /// The configured key source type is not compatible with the token's algorithm.
    #[error("The configured key source is not compatible with the token's algorithm (e.g., JWKS used for HS256)")]
    UnsupportedKeyTypeForAlgorithm,

    /// The key material (e.g., JWKS client) required for validation is missing.
    #[error("Key material required for validation is missing")]
    MissingKeyMaterial,

    /// Nonce validation was required, but no nonce was provided to the validate function.
    #[error("A nonce was expected for validation but was not provided")]
    MissingNonceForValidation,

    /// Nonce validation was required, but the token did not contain a nonce claim.
    #[error("A nonce was expected but not found in the token")]
    MissingNonceInToken,

    /// An error occurred while decoding a Base64URL encoded string.
    #[error("Base64URL decoding error: {0}")]
    Base64DecodeError(#[from] DecodeError),

    /// The grant type in the token request is not supported.
    #[error("Unsupported grant type: {0}")]
    UnsupportedGrantType(String),

    /// The requested scope is invalid, unsupported, or not allowed for the client.
    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    /// Failed to deserialize the token's claims into the target struct.
    #[error("Failed to deserialize claims: {0}")]
    ClaimDeserializationError(String),
}