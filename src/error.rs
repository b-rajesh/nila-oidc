// src/error.rs

use thiserror::Error;

/// The primary error type for the `nila-oidc` library.

pub enum NilaOidcError {
    
    InvalidUrl(String),

    #[error("A required configuration field is missing: {0}")]
    MissingConfiguration(String),

    
    HttpError(#[from] reqwest::Error),

    
    JwtError(#[from] Box<jsonwebtoken::errors::Error>),

    
    UnsupportedAlgorithm(jsonwebtoken::Algorithm),

    
    MissingKeyId,

    
    KeyNotFound(String),
    
    
    InvalidKeyFormat(String),

    #[error("A nonce was expected for validation but was not provided")]
    MissingNonce,

    
    NonceMismatch,
}