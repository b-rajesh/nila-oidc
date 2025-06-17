# nila-oidc
OIDC Library using RUST 1.86.0
# Tech Stack
- RUST 1.86.0
- NilaProxy 0.5.0
- Pingora 0.5.0
- OIDC libraries
## Library Usage Documentation:

The `nila-oidc` library provides a robust way to validate OIDC ID Tokens. Here's how to integrate and use it in your projects:

### 1. Add as a Dependency

Add `nila-oidc` to your project's `Cargo.toml`:

```toml
[dependencies]
nila-oidc = { version = "0.1.0" } # Or use git/path for local development
# If you need Pingora integration features:
# nila-oidc = { version = "0.1.0", features = ["pingora-integration"] }
# If you need Redis caching for JWKS:
# nila-oidc = { version = "0.1.0", features = ["redis-cache"] }
```

### 2. Import Necessary Types

The library provides a `prelude` module for convenience:

```rust
use nila_oidc::prelude::*;
use std::time::Duration; // For specifying durations
```

### 3. Configure the Validator

The `Validator` requires a `Config` object. Use the `ConfigBuilder` to construct it:

```rust
async fn setup_validator() -> Result<Validator, NilaOidcError> {
    let config = ConfigBuilder::new()
        .issuer_url("https://your-oidc-provider.com/.well-known/openid-configuration")? // Or the direct issuer URL
        .client_id("your_client_id_registered_with_provider".to_string())
        // Optional: Override JWKS URI if not discoverable or different
        // .jwks_uri("https://your-oidc-provider.com/jwks")?
        // Optional: Set custom cache TTL for JWKS (if provider doesn't send Cache-Control)
        // .cache_ttl(Duration::from_secs(3600)) // 1 hour
        // Optional: Specify allowed algorithms (defaults to [Algorithm::RS256])
        .algorithms(vec![Algorithm::RS256, Algorithm::ES256])
        // Optional: Adjust clock skew tolerance (defaults to 60 seconds)
        // .leeway(Duration::from_secs(30))
        // Optional: Disable nonce validation (defaults to true)
        // .validate_nonce(false) // If you set this, ensure your ValidationDetails reflects this
        .build()?;

    let validator = Validator::new(config);
    Ok(validator)
}
```

**Configuration Details (`Config` struct):**

*   `issuer_url: Url`: **Required.** The issuer URL of your OIDC provider (e.g., `https://accounts.google.com`). This is used for discovery (to find the JWKS URI) and to validate the `iss` claim in the token.
*   `client_id: String`: **Required.** Your application's client ID, as registered with the OIDC provider. This is used to validate the `aud` (audience) claim in the token.
*   `jwks_uri: Option<Url>`: Optional. If you want to specify the JWKS URI directly, bypassing discovery from the `issuer_url`.
*   `cache_ttl: Duration`: Optional. Fallback Time-To-Live for caching the JSON Web Key Set (JWKS). Defaults to 24 hours. This is used if the OIDC provider's JWKS endpoint doesn't provide `Cache-Control` headers.
*   `validation: ValidationDetails`: Contains specific token validation parameters:
    *   `algorithms: Vec<Algorithm>`: **Required (defaults to `[Algorithm::RS256]`).** A list of JWT signing algorithms that your application will accept.
    *   `leeway: Duration`: Optional (defaults to 60 seconds). A duration to allow for clock skew between your server and the OIDC provider when validating time-based claims like `exp` (expiration) and `iat` (issued at).
    *   `validate_nonce: bool`: Optional (defaults to `true`). Whether to validate the `nonce` claim in the ID token. If `true`, you must provide the expected nonce when calling `validator.validate()`.

### 4. Validate a Token

Once you have a `Validator` instance, you can validate ID tokens:

```rust
// Assuming `validator` is an instance of `Validator`
// and `id_token_string` is the raw token received from the client.
// `expected_nonce` is the nonce you sent during the authorization request.
async fn DANGEROUS_do_validation(validator: &Validator, id_token_string: &str, expected_nonce: Option<&str>) {
    // If you have custom claims, define a struct that derives Deserialize and implements HasNonce
    // #[derive(serde::Deserialize, Debug)]
    // struct MyCustomClaims {
    //     // Standard claims
    //     iss: String,
    //     sub: String,
    //     aud: String,
    //     exp: u64,
    //     iat: u64,
    //     nonce: Option<String>,
    //     // Custom claims
    //     custom_field: String,
    //     another_custom_field: i32,
    // }
    //
    // impl nila_oidc::validator::HasNonce for MyCustomClaims {
    //     fn get_nonce(&self) -> Option<&str> {
    //         self.nonce.as_deref()
    //     }
    // }
    //
    // match validator.validate::<MyCustomClaims>(id_token_string, expected_nonce).await {

    // For standard claims:
    match validator.validate::<Claims>(id_token_string, expected_nonce).await {
        Ok(token_data) => {
            println!("Token is valid!");
            println!("Subject: {}", token_data.claims.sub);
            println!("Issuer: {}", token_data.claims.iss);
            if let Some(nonce) = token_data.claims.get_nonce() {
                println!("Nonce: {}", nonce);
            }
            // You can now trust the claims in token_data.claims
        }
        Err(e) => {
            eprintln!("Token validation failed: {}", e);
            // Handle specific errors, e.g., NilaOidcError::NonceMismatch, NilaOidcError::JwtValidation(...)
            match e {
                NilaOidcError::NonceMismatch => {
                    // Specific handling for nonce mismatch
                }
                NilaOidcError::JwtValidation(jwt_error) => {
                    // Specific handling for JWT errors (e.g., expired token)
                    eprintln!("Underlying JWT error: {:?}", jwt_error.kind());
                }
                _ => {
                    // Generic error handling
                }
            }
        }
    }
}
```

### 5. Error Handling

The `validate` method returns a `Result<TokenData<T>, NilaOidcError>`. Your `NilaOidcError` enum (in `src/error.rs`) defines various error types that can occur, allowing you to handle them appropriately.
