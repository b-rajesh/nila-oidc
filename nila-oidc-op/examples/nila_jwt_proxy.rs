use async_trait::async_trait;
use nila_oidc::prelude::*;
use pingora_core::server::Server;
use pingora_http::ResponseHeader;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, ErrorType, Result};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use std::fs;
use std::time::Duration;
use std::str::FromStr; // Import FromStr
use std::collections::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LoggingConfig {
    //output: Option<String>, // Made optional as we only use level for now
    level: Option<String>,
    //format: Option<String>, // Made optional
    //pretty_print_logs: Option<bool>, // Made optional
}

/// Corresponds to the `token_generator` section in the YAML
#[derive(Debug, Deserialize, Clone)]
struct GeneratorAppConfig { // This remains the same
    issuer: url::Url,
    algorithm: Algorithm,
    token_ttl_seconds: u64,
    signing_key: SigningKeyConfig,
    supported_scopes: Option<String>,
    identity_nila_grant_type_extension: String,
}

/// Corresponds to the `identity_jwt_assertion` section in the YAML
#[derive(Debug, Deserialize)]
struct AssertionAppConfig {
    issuer: String,
    jwks_uri: Option<String>,
    algorithms: Option<Vec<String>>,
    leeway_seconds: Option<u64>,
    validate_nonce: Option<bool>,
    cache_ttl_seconds: Option<u64>,
    assert_claims: Option<HashMap<String, serde_json::Value>>, // This now includes audience
}
#[derive(Debug, Deserialize)]
struct ProxyAppConfig {
    identity_jwt_assertion: AssertionAppConfig,
    identity_nila_op: Option<GeneratorAppConfig>,
    clients: HashMap<String, ClientDetails>,
    logging: Option<LoggingConfig>, // Updated to nested logging config
    listen_addr: String,
    upstream_addr: String,
}

#[derive(Clone)] // HttpPeer needs to be Clone
struct UpstreamConfig {
    addr: String,
    tls: bool, // Assuming HttpPeer::new takes (addr, tls, sni)
    sni: String,
}
struct JwtAuthService {
    validator: Arc<Validator>,
    generator: Option<Arc<Generator>>, // Generator is optional
    upstream: UpstreamConfig,
}

/// Represents the form body of a client credentials request
#[derive(Deserialize)]
struct TokenRequestBody {
    grant_type: String,
    client_id: String,
    client_secret: Option<String>,
    scope: Option<String>,
}

#[async_trait]
impl ProxyHttp for JwtAuthService {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // --- Handle special, unauthenticated endpoints first ---

        // Endpoint to expose the generator's public key set (JWKS)
        if session.req_header().uri.path() == "/.well-known/jwks.json" && session.req_header().method == "GET" {
            if let Some(generator) = &self.generator {
                if let Some(jwks_response) = generator.get_public_jwks() {
                    let mut resp_header = ResponseHeader::build(200, None)?;
                    resp_header.insert_header("Content-Type", "application/json")?;
                    let body_bytes = jwks_response.to_string().into_bytes();
                    resp_header.insert_header("Content-Length", body_bytes.len().to_string())?;
                    session.write_response_header(Box::new(resp_header), false).await?;
                    session.write_response_body(Some(body_bytes.into()), true).await?;
                } else {
                    // Generator is configured but for a symmetric key (e.g., HS256), so no public keys to expose.
                    tracing::warn!("Request to /jwks but no public key is available (likely using symmetric key).");
                    session.respond_error(404).await?;
                }
            } else {
                // Token generator is not configured at all.
                tracing::error!("/jwks endpoint called but identity_nila_op is not configured.");
                session.respond_error(501).await?; // Not Implemented
            }
            return Ok(true); // Request handled, stop processing.
        }

        // Endpoint for the OAuth2 token grant
        if session.req_header().uri.path() == "/token" && session.req_header().method == "POST" { // Correctly access the path
            if let Some(generator) = &self.generator {
                // Read and parse the request body
                let body = session.read_request_body().await?;
                let body_bytes = body.unwrap_or_default();
                let params: TokenRequestBody = match serde_urlencoded::from_bytes(&body_bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("Failed to parse token request body: {}", e);
                        session.respond_error(400).await?;
                        return Ok(true);
                    }
                };

                // Issue the token
                let client_secret = params.client_secret.as_deref().unwrap_or("");
                match generator.issue_token(
                    &params.client_id,
                    client_secret,
                    &params.grant_type,
                    params.scope.as_deref(),
                ) {
                    Ok(access_token) => {
                        let response_body = serde_json::json!({
                            "access_token": access_token,
                            "token_type": "Bearer",
                            "expires_in": generator.config.token_ttl_seconds
                        });
                        let mut resp_header = ResponseHeader::build(200, None)?;
                        resp_header.insert_header("Content-Type", "application/json")?;
                        let body_bytes = response_body.to_string().into_bytes();
                        resp_header.insert_header("Content-Length", body_bytes.len().to_string())?;
                        session.write_response_header(Box::new(resp_header), false).await?;
                        session.write_response_body(Some(body_bytes.into()), true).await?;
                    }
                    Err(NilaOidcError::InvalidClientCredentials) => {
                        tracing::warn!("Invalid client credentials for client_id: {}", params.client_id);
                        session.respond_error(401).await?;
                    }
                    Err(NilaOidcError::UnsupportedGrantType(grant)) => {
                        tracing::warn!("Unsupported grant_type: {}", grant);
                        session.respond_error(400).await?;
                    }
                    Err(NilaOidcError::InvalidScope(scope_err)) => {
                        tracing::warn!("Invalid scope requested: {}", scope_err);
                        session.respond_error(400).await?;
                    }
                    Err(e) => {
                        tracing::error!("Token generation error: {}", e);
                        session.respond_error(500).await?;
                    }
                }
            } else {
                // Token generator is not configured
                tracing::error!("Token endpoint called but identity_nila_op is not configured.");
                session.respond_error(501).await?; // Not Implemented
            }
            return Ok(true); // Request is handled, stop processing.
        }

        // --- Default behavior: JWT validation for all other paths ---

        if let Some(auth_header) = session.req_header().headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    // For this example, we are not validating nonce.
                    // In a real OIDC flow, you would pass the expected nonce.
                    match self.validator.validate::<Claims>(token, None).await {
                        Ok(token_data) => {
                            println!("Token validated successfully for sub: {}", token_data.claims.sub);
                            // Optionally, add claims to request headers for upstream
                            // session.req_header_mut().insert_header("X-User-Subject", token_data.claims.sub)?;
                            return Ok(false); // Continue to upstream
                        }
                        Err(e) => {
                            tracing::warn!("Token validation failed: {}", e);
                            let _ = session.respond_error(401).await;
                            return Ok(true); // Filtered, request ends
                        }
                    }
                }
            }
        }

        // No Bearer token found or malformed header
        tracing::warn!("Missing or malformed Authorization: Bearer token");
        let _ = session.respond_error(401).await;
        Ok(true) // Filtered, request ends
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Use configured upstream
        let peer = Box::new(HttpPeer::new(
            &self.upstream.addr,
            self.upstream.tls,
            self.upstream.sni.clone(),
        ));
        Ok(peer)
    }
}

/// Sets up the token generator (Identity Provider) from the application configuration.
fn setup_token_generator(
    op_config: &Option<GeneratorAppConfig>,
    clients: &HashMap<String, ClientDetails>,
) -> Result<Option<Arc<Generator>>, Box<Error>> {
    if let Some(gen_config_app) = op_config {
        tracing::info!("Identity Provider (OP) generator configured.");
        let gen_config = GeneratorConfig {
            issuer: gen_config_app.issuer.clone(),
            algorithm: gen_config_app.algorithm,
            clients: clients.clone(),
            signing_key: gen_config_app.signing_key.clone(),
            token_ttl_seconds: gen_config_app.token_ttl_seconds,
            supported_scopes: gen_config_app.supported_scopes.clone(),
            identity_nila_grant_type_extension: gen_config_app.identity_nila_grant_type_extension.clone(),
        };
        let generator = Generator::new(gen_config).map_err(|e| {
            let mut err = Error::new(ErrorType::InternalError);
            tracing::error!("Failed to create token generator: {:?}", e);
            err.set_context(e.to_string());
            err
        })?;
        Ok(Some(Arc::new(generator)))
    } else {
        tracing::info!("Token generator (identity_nila_op) not configured.");
        Ok(None)
    }
}

/// Sets up the JWT assertion (Validator) from the application configuration.
fn setup_jwt_assertion(
    config: &AssertionAppConfig,
) -> Result<Arc<Validator>, Box<Error>> {
    tracing::info!("Setting up JWT assertion (validator)...");

    let mut oidc_builder = ConfigBuilder::new()
        .issuer_url(&config.issuer)
        .map_err(|e| {
            let mut err = Error::new(ErrorType::InternalError);
            err.set_context(format!("NilaOIDC config error for issuer_url: {:?}", e));
            err
        })?;
    if let Some(jwks_uri_str) = &config.jwks_uri {
        oidc_builder = oidc_builder.jwks_uri(jwks_uri_str).map_err(|e| {
            let mut err = Error::new(ErrorType::InternalError);
            err.set_context(format!("NilaOIDC config error (jwks_uri): {}", e));
            err
        })?;
        tracing::info!("Using direct JWKS URI: {}", jwks_uri_str);
    }

    if let Some(algs_str) = &config.algorithms {
        let algorithms: std::result::Result<Vec<Algorithm>, _> = algs_str
            .iter()
            .map(|s| Algorithm::from_str(s).map_err(|_| format!("Invalid algorithm string: {}", s)))
            .collect();
        oidc_builder = oidc_builder.algorithms(algorithms.map_err(|e| {
            let mut err = Error::new(ErrorType::InternalError);
            err.set_context(e);
            err
        })?);
    }

    if let Some(leeway_s) = config.leeway_seconds {
        oidc_builder = oidc_builder.leeway(Duration::from_secs(leeway_s));
    }

    let should_validate_nonce = config.validate_nonce.unwrap_or(true);
    oidc_builder = oidc_builder.validate_nonce(should_validate_nonce);

    if let Some(ttl_seconds) = config.cache_ttl_seconds {
        oidc_builder = oidc_builder.cache_ttl(Duration::from_secs(ttl_seconds));
    }

    if let Some(claims_to_assert) = &config.assert_claims {
        oidc_builder = oidc_builder.assert_claims(claims_to_assert.clone());
    }

    let oidc_config = oidc_builder.build().map_err(|e| {
        let mut err = Error::new(ErrorType::InternalError);
        err.set_context(format!("NilaOIDC config build error: {:?}", e));
        err
    })?;

    Ok(Arc::new(Validator::new(oidc_config)))
}

fn main() -> Result<()> { // Changed to synchronous main
    // --- Load Configuration from YAML (early, for log_level) ---
    let config_path = "examples/proxy_config.yaml";
    let config_str = fs::read_to_string(config_path)
        .map_err(|e| {
            let mut err = Error::new(ErrorType::ReadError);
            err.set_context(format!("Failed to read config file {}: {:?}", config_path, e));
            err
        })?;
    let app_config: ProxyAppConfig = serde_yaml::from_str(&config_str)
        .map_err(|e| {
            let mut err = Error::new(ErrorType::InternalError);
            err.set_context(format!("Failed to parse YAML config from {}: {:?}", config_path, e));
            err
        })?;

    // Initialize tracing subscriber based on config
    let log_level_str = app_config.logging.as_ref()
        .and_then(|l| l.level.as_deref())
        .unwrap_or("info"); // Default to "info"

    let log_level = tracing::Level::from_str(log_level_str).unwrap_or(tracing::Level::INFO);
    let subscriber_builder = tracing_subscriber::fmt().with_max_level(log_level);

    // Note: The 'format' and 'pretty_print_logs' from YAML are not used by this basic fmt subscriber setup.
    // For JSON output or more complex formatting, you'd use other layers/formatters from tracing_subscriber.
    subscriber_builder.init();

    tracing::info!("Log level set to: {}", log_level);
    dbg!(&app_config); // Keep this for inspecting the full deserialized config

    // 1. Create a Tokio runtime manually
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| { // Corrected error mapping
            let mut err = Error::new(ErrorType::InternalError);
            err.set_context(format!("Failed to create Tokio runtime: {:?}", e));
            // err is already a Box<ErrorInner>, which is what pingora_core::Error is.
            err 
        })?;

    // 2. Execute async setup logic within the runtime's context, using the already parsed app_config
    // Note: We clone app_config here if it's needed later outside the block_on,
    // or pass references if appropriate. For this example, using it directly is fine.
    let (jwt_auth_service, app_listen_addr_from_config) = runtime.block_on(async {
        // --- Configure Nila OIDC Validator ---
        // Setup generator first, as its JWKS endpoint might be used by the validator.
        let generator = setup_token_generator(&app_config.identity_nila_op, &app_config.clients)?;

        // Setup validator.
        let validator = setup_jwt_assertion(&app_config.identity_jwt_assertion)?;

        let upstream_sni = app_config.upstream_addr.split(':').next().unwrap_or(&app_config.upstream_addr).to_string();
        let upstream_config = UpstreamConfig {
            addr: app_config.upstream_addr.clone(),
            tls: false,
            sni: upstream_sni,
        };

        Ok::<_, Box<Error>>((JwtAuthService { validator, generator, upstream: upstream_config }, app_config.listen_addr.clone()))
    })?; // The error from block_on's future is now Box<Error>

    // --- Configure Pingora Server ---
    // Server::new(None, None) will create its own internal runtime.
    // The JwksClient's background task will run on the 'runtime' created at the start of main.
    let mut my_server = Server::new(None)?; // Pass None for conf_path to use default config and runtime creation
    my_server.bootstrap();

    let mut proxy_service = pingora_proxy::http_proxy_service(&my_server.configuration, jwt_auth_service);
    proxy_service.add_tcp(&app_listen_addr_from_config);

    tracing::info!("Pingora JWT proxy listening on {}", app_listen_addr_from_config);
    tracing::info!("Token endpoint available at POST http://localhost:6188/token");
    //tracing::info!("JWKS endpoint available at GET(if asymmetric key is used)", jwks_uri_str);
    tracing::info!("Test with: curl -v -H \"Authorization: Bearer <YOUR_JWT_TOKEN>\" http://localhost:6188/");

    my_server.add_service(proxy_service);
    my_server.run_forever();
 }