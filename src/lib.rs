// src/lib.rs


pub mod error;
pub mod generator;
pub mod validator;

/// The public prelude for the `nila-oidc` crate.
///
/// This module re-exports the most commonly used types for convenience.
pub mod prelude {
    pub use crate::error::NilaOidcError;

    pub use crate::generator::{
        ClientDetails, Generator, GeneratorConfig, SigningKeyConfig,
    };
    pub use crate::validator::{
        config::{Config, ConfigBuilder},
        Claims, Validator,
    };

    pub use jsonwebtoken::Algorithm;
}