// src/lib.rs

pub mod client;
pub mod config;
pub mod error;
pub mod generator;
pub mod model;
pub mod validator;

/// The public prelude for the `nila-oidc` crate.
///
/// This module re-exports the most commonly used types for convenience.
pub mod prelude {
    pub use crate::error::NilaOidcError;
    pub use crate::config::{Config, ConfigBuilder}; // Use top-level config module

    pub use crate::generator::{
        ClientDetails, Generator, GeneratorConfig, SigningKeyConfig,
    };
    pub use crate::validator::{
        Claims, HasNonce, Validator,
    };

    pub use jsonwebtoken::Algorithm;
}