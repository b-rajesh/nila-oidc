// src/client.rs

use crate::error::NilaOidcError;
use super::model::{JsonWebKeySet, OidcDiscoveryDocument};
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, instrument};
use url::Url;

/// A client for fetching and caching JSON Web Keys (JWKs) from an OIDC provider.
#[derive(Clone)]
pub struct JwksClient {
    // The client is internally ref-counted to allow for cheap cloning.
    inner: Arc<Inner>,
}

struct Inner {
    http_client: reqwest::Client,
    issuer_url: Url, // Needed for discovery if jwks_uri_override is None
    jwks_uri_override: Option<Url>,
    default_cache_ttl: Duration,
    // Cache stores `kid` -> `DecodingKey`.
    key_cache: Cache<String, Arc<DecodingKey>>,
}

impl JwksClient {
    /// Creates a new `JwksClient`.
    ///
    /// This will also spawn a background task to proactively refresh the keys before they expire.
    pub fn new(
        issuer_url: Url,
        jwks_uri_override: Option<Url>,
        default_cache_ttl: Duration,
    ) -> Self {
        let inner = Arc::new(Inner {
            http_client: reqwest::Client::new(),
            key_cache: Cache::new(100), // Max 100 keys, should be more than enough.
            issuer_url,
            jwks_uri_override,
            default_cache_ttl,
        });

        let client = Self { inner };

        // Spawn the background refresh task.
        let refresh_client = client.clone();
        tokio::spawn(async move {
            refresh_client.key_refresh_loop().await;
        });

        client
    }

    /// Retrieves a decoding key for the given Key ID (`kid`).
    ///
    /// It first checks the in-memory cache. If the key is not found (cache miss),
    /// it will fetch the entire JWKS from the provider, populate the cache, and
    /// then return the key.
    #[instrument(skip(self), err)]
    pub async fn get_key(&self, kid: &str) -> Result<Arc<DecodingKey>, NilaOidcError> {
        if let Some(key) = self.inner.key_cache.get(kid).await { // moka's get is sync
            debug!("JWK cache hit for kid: {}", kid);
            return Ok(key);
        }

        debug!("JWK cache miss for kid: {}. Fetching from provider.", kid);
        self.fetch_and_cache_keys().await?;

        // Try getting from the cache again after fetching.
        self.inner
            .key_cache
            .get(kid)
            .await
            .ok_or_else(|| NilaOidcError::KeyNotFound(kid.to_string()))

    }

    /// The main loop for the background key refresh task.
    async fn key_refresh_loop(&self) {
        let base_retry_delay = Duration::from_secs(5);
        let max_retry_delay = Duration::from_secs(300); // 5 minutes
        let mut current_retry_delay = base_retry_delay;

        loop {
            let ttl = match self.fetch_and_cache_keys().await {
                Ok(duration) => {
                    // On success, reset the retry delay for the next potential failure.
                    current_retry_delay = base_retry_delay;
                    duration
                }
                Err(e) => {
                    error!("Failed to refresh JWKS in background: {:?}. Retrying in {:?}.", e, current_retry_delay);
                    tokio::time::sleep(current_retry_delay).await;
                    // Double the delay for the next attempt, up to the max.
                    current_retry_delay = (current_retry_delay * 2).min(max_retry_delay);
                    continue; // Skip the proactive refresh sleep and retry immediately after the delay.
                }
            };

            // Proactively refresh before the cache actually expires.
            // Refresh at 80% of the TTL's lifetime.
            let refresh_interval = Duration::from_secs_f64(ttl.as_secs_f64() * 0.8);
            debug!("JWKS background refresh scheduled in {:?}", refresh_interval);
            tokio::time::sleep(refresh_interval).await;
        }
    }

    /// Fetches the JWKS from the OIDC provider and populates the cache.
    /// Returns the cache TTL for the fetched keys.
    #[instrument(skip(self), err)]
    async fn fetch_and_cache_keys(&self) -> Result<Duration, NilaOidcError> {
        let jwks_uri = self.get_jwks_uri().await?;

        let response = self.inner.http_client.get(jwks_uri).send().await?;

        let cache_ttl = self.parse_cache_control(&response).unwrap_or(self.inner.default_cache_ttl);

        let jwks: JsonWebKeySet = response.json().await?;

        debug!("Successfully fetched {} keys. Caching with TTL: {:?}", jwks.keys.len(), cache_ttl);

        for jwk in jwks.keys {
            if jwk.kty == "RSA" {
                // Ensure n and e are present for RSA keys
                let n = jwk.n.as_deref().ok_or_else(|| NilaOidcError::InvalidKeyFormat("RSA key missing 'n' component".to_string()))?;
                let e = jwk.e.as_deref().ok_or_else(|| NilaOidcError::InvalidKeyFormat("RSA key missing 'e' component".to_string()))?;
                let decoding_key = DecodingKey::from_rsa_components(n, e)?;
                self.inner.key_cache.insert(jwk.kid, Arc::new(decoding_key)).await;
            }
        }

        Ok(cache_ttl)
    }

    /// Determines the JWKS URI, either from config override or OIDC discovery.
    async fn get_jwks_uri(&self) -> Result<Url, NilaOidcError> {
        if let Some(uri) = self.inner.jwks_uri_override.clone() {
            debug!("Using JWKS URI from config override: {}", uri);
            return Ok(uri);
        }

        let discovery_url = self.inner.issuer_url.join(".well-known/openid-configuration")
           .map_err(|e| NilaOidcError::InvalidUrl(e.to_string()))?;

        debug!("Performing OIDC discovery at: {}", discovery_url);
        let discovery_doc: OidcDiscoveryDocument = self.inner.http_client.get(discovery_url).send().await?.json().await?;

        Url::parse(&discovery_doc.jwks_uri).map_err(|e| NilaOidcError::InvalidUrl(e.to_string()))
    }

    /// Parses the `Cache-Control` header to determine the TTL.
    fn parse_cache_control(&self, response: &reqwest::Response) -> Option<Duration> {
        response.headers()
           .get(reqwest::header::CACHE_CONTROL)?
           .to_str().ok()?
           .split(',')
           .find_map(|part| {
                let part = part.trim();
                if part.starts_with("max-age=") {
                    part.strip_prefix("max-age=")?
                       .parse::<u64>().ok()
                       .map(Duration::from_secs)
                } else {
                    None
                }
            })
    }
}