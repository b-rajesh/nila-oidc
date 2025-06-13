// src/error.rs

use thiserror::Error as error;

/// The primary error type for the `nila-oidc` library.

pub enum NilaOidcError {
    
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("A required configuration field is missing: {0}")]
    MissingConfiguration(String),

    
    #[error("HTTP request error: {0}")]
    HttpError(#[from] reqwest::Error),

    
    #[error("JWT error: {0}")]
    JwtError(#[from] Box<jsonwebtoken::errors::Error>),

    
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
}