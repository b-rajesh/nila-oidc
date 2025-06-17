use async_trait::async_trait;
use nila_oidc::prelude::*;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, ErrorType, Result};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use std::fs;
use std::time::Duration;
use std::str::FromStr; // Import FromStr
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ProxyAppConfig {
    issuer_url: String,
    client_id: String,
    jwks_uri: Option<String>, // Optional direct JWKS URI
    algorithms: Option<Vec<String>>,
    leeway_seconds: Option<u64>,
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
    upstream: UpstreamConfig,
}

#[async_trait]
impl ProxyHttp for JwtAuthService {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
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
                            eprintln!("Token validation failed: {}", e);
                            let _ = session.respond_error(401).await;
                            return Ok(true); // Filtered, request ends
                        }
                    }
                }
            }
        }

        // No Bearer token found or malformed header
        eprintln!("Missing or malformed Authorization: Bearer token");
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

fn main() -> Result<()> { // Changed to synchronous main
    // Initialize logger (optional)
    // env_logger::init();

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

    // 2. Execute async setup logic within the runtime's context
    let (jwt_auth_service, app_listen_addr) = runtime.block_on(async {
        // --- Load Configuration from YAML ---
        // Map std::io::Error to pingora_core::Error
        let config_path = "examples/proxy_config.yaml";
        let config_str = fs::read_to_string(config_path)
            .map_err(|e| {
                let mut err = Error::new(ErrorType::ReadError);
                err.set_context(format!("Failed to read config file {}: {:?}", config_path, e)); // Ensure {:?} is used for e
                err // Return Error directly, ? will box it
            })?;

        // Map serde_yaml::Error to pingora_core::Error
        let app_config: ProxyAppConfig = serde_yaml::from_str(&config_str)
            .map_err(|e| {
                let mut err = Error::new(ErrorType::InternalError);
                err.set_context(format!("Failed to parse YAML config from {}: {:?}", config_path, e)); // Ensure {:?} is used for e
                err // Return Error directly, ? will box it
            })?;

        // --- Configure Nila OIDC Validator ---
        let mut oidc_builder = ConfigBuilder::new()
            .issuer_url(&app_config.issuer_url)
            .map_err(|e| {
                let mut err = Error::new(ErrorType::InternalError);
                err.set_context(format!("NilaOIDC config error for issuer_url: {:?}", e)); // Ensure {:?} is used for e
                err // Return Error directly, ? will box it
            })?
            .client_id(app_config.client_id.clone());

        if let Some(jwks_uri_str) = &app_config.jwks_uri {
            oidc_builder = oidc_builder.jwks_uri(jwks_uri_str)
                .map_err(|e| {
                    let mut err = Error::new(ErrorType::InternalError);
                    err.set_context(format!("NilaOIDC config error (jwks_uri): {}", e));
                    err // For NilaOidcError, {} should be fine due to thiserror, but {:?} is safer if issues persist.
                })?;
            println!("Using direct JWKS URI: {}", jwks_uri_str);
        }

        if let Some(algs_str) = &app_config.algorithms {
            let algorithms_res: std::result::Result<Vec<Algorithm>, Box<Error>> = algs_str
                .iter()
                .map(|s_val| Algorithm::from_str(s_val).map_err(|_| { 
                    let mut err = Error::new(ErrorType::InternalError);
                    err.set_context(format!("Invalid algorithm string: {}", s_val));
                    err
                }))
                .collect();
            oidc_builder = oidc_builder.algorithms(algorithms_res?);
        }

        if let Some(leeway_s) = app_config.leeway_seconds {
            oidc_builder = oidc_builder.leeway(Duration::from_secs(leeway_s));
        }

        let oidc_config = oidc_builder.build()
            .map_err(|e| {
                let mut err = Error::new(ErrorType::InternalError);
                err.set_context(format!("NilaOIDC config build error: {:?}", e)); // Ensure {:?} is used for e
                err // Return Error directly, ? will box it
            })?;

        let validator = Arc::new(Validator::new(oidc_config));

        let upstream_sni = app_config.upstream_addr.split(':').next().unwrap_or(&app_config.upstream_addr).to_string();
        let upstream_config = UpstreamConfig {
            addr: app_config.upstream_addr.clone(),
            tls: false,
            sni: upstream_sni,
        };

        Ok::<_, Box<Error>>((JwtAuthService { validator, upstream: upstream_config }, app_config.listen_addr))
    })?; // The error from block_on's future is now Box<Error>

    // --- Configure Pingora Server ---
    // Server::new(None, None) will create its own internal runtime.
    // The JwksClient's background task will run on the 'runtime' created at the start of main.
    let mut my_server = Server::new(None)?; // Pass None for conf_path to use default config and runtime creation
    my_server.bootstrap();

    let mut proxy_service = pingora_proxy::http_proxy_service(&my_server.configuration, jwt_auth_service);
    proxy_service.add_tcp(&app_listen_addr);

    println!("Pingora JWT proxy listening on {}", app_listen_addr);
    println!("Test with: curl -v -H \"Authorization: Bearer <YOUR_JWT_TOKEN>\" http://localhost:6188/");

    my_server.add_service(proxy_service);
    my_server.run_forever();
}

// Helper to allow disabling nonce validation via builder (Optional enhancement for config.rs)
// If you add this to config.rs:
// pub fn validate_nonce(mut self, validate: bool) -> Self {
//     self.validation.validate_nonce = validate;
//     self
// }