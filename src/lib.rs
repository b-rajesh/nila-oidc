// src/lib.rs


pub mod client;
pub mod config;
pub mod error;
pub mod model;
pub mod validator;

/// The public prelude for the `pingora-oidc` crate.
///
/// This module re-exports the most commonly used types for convenience.
pub mod prelude {
    pub use crate::config::{Config, ConfigBuilder};
    pub use crate::error::NilaOidcError;
    pub use crate::validator::{Claims, Validator};
    pub use jsonwebtoken::Algorithm;
}