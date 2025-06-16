// src/error.rs

use thiserror::Error;

/// The primary error type for the `nila-oidc` library.
#[derive(Debug, Error)]
pub enum NilaOidcError {
    #[error("JWT validation error: {0}")]
    JwtValidation(#[from] jsonwebtoken::errors::Error), // If you want to automatically convert from jsonwebtoken::Error

    #[error("Nonce validation is enabled, but no nonce was provided for verification")]
    MissingNonceForValidation,

    #[error("Nonce validation is enabled, but the token does not contain a nonce claim")]
    MissingNonceInToken,


    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("A required configuration field is missing: {0}")]
    MissingConfiguration(String),

    #[error("HTTP request error")]
    HttpError(#[from] reqwest::Error),


    #[error("Unsupported JWT algorithm: {0:?}")]
    UnsupportedAlgorithm(jsonwebtoken::Algorithm),

    #[error("The JWT header is missing the 'kid' (Key ID) field")]
    MissingKeyId,

    #[error("Key not found for kid: {0}")]
    KeyNotFound(String),

    #[error("Invalid JWK format: {0}")]
    InvalidKeyFormat(String),

    #[error("A nonce was expected for validation but was not provided")]
    MissingNonce,

    #[error("Nonce mismatch: the nonce in the token does not match the expected nonce")]
    NonceMismatch,

    #[error("Base64 decoding error")]
    Base64DecodeError(#[from] base64_url::base64::DecodeError),
    
}