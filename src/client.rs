// src/client.rs

use crate::config::Config;
use crate::error::NilaOidcError;
use crate::model::{JsonWebKeySet, OidcDiscoveryDocument};
use jsonwebtoken::{DecodingKey, Header};
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, instrument};
use url::Url;

/// A client for fetching and caching JSON Web Keys (JWKs) from an OIDC provider.
#[derive(Clone)]
pub struct JwksClient {
    // The client is internally ref-counted to allow for cheap cloning.
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    http_client: reqwest::Client,
    // Cache stores `kid` -> `DecodingKey`.
    key_cache: Cache<String, Arc<DecodingKey>>,
}

impl JwksClient {
    /// Creates a new `JwksClient`.
    ///
    /// This will also spawn a background task to proactively refresh the keys before they expire.
    pub fn new(config: Config) -> Self {
        let inner = Arc::new(Inner {
            config,
            http_client: reqwest::Client::new(),
            key_cache: Cache::new(100), // Max 100 keys, should be more than enough.
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
        if let Some(key) = self.inner.key_cache.get(kid).await {
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
        loop {
            let ttl = match self.fetch_and_cache_keys().await {
                Ok(duration) => duration,
                Err(e) => {
                    error!("Failed to refresh JWKS in background: {:?}. Retrying in 60s.", e);
                    Duration::from_secs(60)
                }
            };

            // Proactively refresh before the cache actually expires.
            // Refresh at 80% of the TTL's lifetime.
            let refresh_interval = Duration::from_secs_f64(ttl.as_secs_f64() * 0.8);
            info!("JWKS background refresh scheduled in {:?}", refresh_interval);
            tokio::time::sleep(refresh_interval).await;
        }
    }

    /// Fetches the JWKS from the OIDC provider and populates the cache.
    /// Returns the cache TTL for the fetched keys.
    #[instrument(skip(self), err)]
    async fn fetch_and_cache_keys(&self) -> Result<Duration, NilaOidcError> {
        let jwks_uri = self.get_jwks_uri().await?;

        let response = self.inner.http_client.get(jwks_uri).send().await?;
        
        let cache_ttl = self.parse_cache_control(&response).unwrap_or(self.inner.config.cache_ttl);

        let jwks: JsonWebKeySet = response.json().await?;

        info!("Successfully fetched {} keys. Caching with TTL: {:?}", jwks.keys.len(), cache_ttl);

        for jwk in jwks.keys {
            // We only support RSA keys for now, as they are the most common for OIDC.
            if jwk.kty == "RSA" {
                let decoding_key = DecodingKey::from_rsa_components(
                    jwk.n.as_ref().ok_or(NilaOidcError::InvalidKeyFormat("missing 'n'".into()))?,
                    jwk.e.as_ref().ok_or(NilaOidcError::InvalidKeyFormat("missing 'e'".into()))?,
                ).map_err(|e| NilaOidcError::JwtError(e.into()))?;
                
                self.inner.key_cache.insert_with_ttl(jwk.kid, Arc::new(decoding_key), cache_ttl).await;
            }
        }

        Ok(cache_ttl)
    }
    
    /// Determines the JWKS URI, either from config override or OIDC discovery.
    async fn get_jwks_uri(&self) -> Result<Url, NilaOidcError> {
        if let Some(uri) = self.inner.config.jwks_uri.clone() {
            debug!("Using JWKS URI from config override: {}", uri);
            return Ok(uri);
        }
        
        let discovery_url = self.inner.config.issuer_url.join(".well-known/openid-configuration")
           .map_err(|e| NilaOidcError::InvalidUrl(e.to_string()))?;

        debug!("Performing OIDC discovery at: {}", discovery_url);
        let discovery_doc: OidcDiscoveryDocument = self.inner.http_client.get(discovery_url).send().await?.json().await?;
        
        let jwks_uri = Url::parse(&discovery_doc.jwks_uri).map_err(|e| NilaOidcError::InvalidUrl(e.to_string()))?;
        debug!("Discovered JWKS URI: {}", jwks_uri);
        Ok(jwks_uri)
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