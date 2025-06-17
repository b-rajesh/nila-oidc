// src/config.rs

use crate::error::NilaOidcError;
use jsonwebtoken::Algorithm;
use std::time::Duration;
use url::Url;

/// Contains the validation settings for an OIDC ID Token.
///
/// This struct is used to configure the specific checks that will be performed
/// on the token's claims, such as allowed algorithms and clock skew tolerance.

#[derive(Clone)] pub struct ValidationDetails {
    /// The signing algorithms that are permitted for the ID Token.
    /// Tokens signed with any other algorithm will be rejected.
    pub algorithms: Vec<Algorithm>,
    /// The tolerance for clock skew when validating time-based claims like `exp` and `iat`.
    /// Defaults to 60 seconds.
    pub leeway: Duration,
    /// Whether to validate the `nonce` claim. If set to `true`, the `validate` method
    /// will require a `nonce` to be passed and will check it against the token's claim.
    pub validate_nonce: bool,
}

impl Default for ValidationDetails {
    fn default() -> Self {
        Self {
            // Default to RS256, the most common algorithm for OIDC.
            algorithms: vec![Algorithm::RS256],
            leeway: Duration::from_secs(60),
            validate_nonce: true,
        }
    }
}

/// Defines the source for JWT validation keys.
#[derive(Clone)]
pub enum KeySourceConfig {
    /// Keys are fetched from a JWKS endpoint.
    Jwks {
        /// Optional override for the JWKS endpoint URL. If `None`, the URL will be
        /// discovered from the issuer's `.well-known/openid-configuration` endpoint.
        jwks_uri: Option<Url>,
        /// The duration for which the fetched JWKS will be cached if no `Cache-Control` header is present.
        cache_ttl: Duration,
    },
    /// A shared secret is used for symmetric key algorithms (e.g., HS256).
    SharedSecret(Vec<u8>),
}
/// The main configuration for the `nila-oidc` validator.
///
/// This struct holds all necessary information to connect to the OIDC provider
/// and validate tokens. It should be constructed using the `ConfigBuilder`.

#[derive(Clone)] pub struct Config {
    /// The issuer URL of the OIDC provider. This is used for discovery and to
    /// validate the `iss` claim of the ID Token.
    pub issuer_url: Url,
    /// The client ID of the application, as registered with the OIDC provider.
    /// This is used to validate the `aud` claim of the ID Token.
    pub client_id: String,
    /// The specific validation parameters to apply to the token.
    pub validation: ValidationDetails,
    /// The source for obtaining JWT validation keys.
    pub key_source: KeySourceConfig,
}

/// A builder for creating a `Config` instance.
///
/// This builder provides a fluent API to ensure that the configuration is
/// constructed correctly and with all required fields.

#[derive(Default)] pub struct ConfigBuilder {
    issuer_url: Option<Url>,
    client_id: Option<String>,
    jwks_uri_option: Option<Url>, // Renamed to avoid conflict with method
    cache_ttl_option: Option<Duration>, // Renamed for clarity
    shared_secret_option: Option<Vec<u8>>,
    validation: ValidationDetails,
}

impl ConfigBuilder {
    /// Creates a new `ConfigBuilder`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the issuer URL of the OIDC provider. This is a required field.
    ///
    /// # Arguments
    ///
    /// * `url` - The issuer URL, e.g., "https://accounts.google.com".
    pub fn issuer_url(mut self, url: &str) -> Result<Self, NilaOidcError> {
        let parsed_url = Url::parse(url).map_err(|e| NilaOidcError::InvalidUrl(e.to_string()))?;
        self.issuer_url = Some(parsed_url);
        Ok(self)
    }

    /// Sets the client ID of the application. This is a required field.
    pub fn client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    /// Sets an explicit JWKS URI, bypassing OIDC discovery. This is optional.
    pub fn jwks_uri(mut self, url: &str) -> Result<Self, NilaOidcError> {
        if self.shared_secret_option.is_some() {
            return Err(NilaOidcError::AmbiguousKeySource("Cannot set JWKS URI when a shared secret is already configured.".to_string()));
        }
        let parsed_url = Url::parse(url).map_err(|e| NilaOidcError::InvalidUrl(e.to_string()))?;
        self.jwks_uri_option = Some(parsed_url);
        Ok(self)
    }

    /// Sets the fallback cache TTL for the JWKS. This is optional.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl_option = Some(ttl);
        self
    }

    /// Sets the allowed signing algorithms.
    /// Defaults to `[Algorithm::RS256]` if not set.
    pub fn algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.validation.algorithms = algorithms;
        self
    }

    /// Sets the clock skew tolerance. This is optional.
    /// Defaults to 60 seconds.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.validation.leeway = leeway;
        self
    }

    /// Sets the shared secret for symmetric key algorithms (e.g., HS256).
    /// This is mutually exclusive with providing a JWKS URI.
    pub fn shared_secret(mut self, secret: Vec<u8>) -> Result<Self, NilaOidcError> {
        if self.jwks_uri_option.is_some() {
            return Err(NilaOidcError::AmbiguousKeySource("Cannot set shared secret when a JWKS URI is already configured.".to_string()));
        }
        self.shared_secret_option = Some(secret);
        Ok(self)
    }
    /// Consumes the builder and returns a `Config` object.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields (`issuer_url`, `client_id`) are missing.
    pub fn build(self) -> Result<Config, NilaOidcError> {
        let issuer_url = self.issuer_url.ok_or(NilaOidcError::MissingConfiguration("issuer_url".to_string()))?;
        let client_id = self.client_id.ok_or(NilaOidcError::MissingConfiguration("client_id".to_string()))?;

        let key_source = if let Some(secret) = self.shared_secret_option {
            if self.jwks_uri_option.is_some() {
                 // This check is also in the setters, but good for belt-and-suspenders
                return Err(NilaOidcError::AmbiguousKeySource("Both shared secret and JWKS URI configured.".to_string()));
            }
            KeySourceConfig::SharedSecret(secret)
        } else {
            // If no shared secret, JWKS is the source (either direct URI or via discovery)
            KeySourceConfig::Jwks {
                jwks_uri: self.jwks_uri_option,
                cache_ttl: self.cache_ttl_option.unwrap_or_else(|| Duration::from_secs(24 * 60 * 60)),
            }
        };

        Ok(Config {
            issuer_url,
            client_id,
            validation: self.validation,
            key_source,
        })
    }
}