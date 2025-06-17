# Nila OIDC Examples

This directory contains example applications demonstrating how to use the `nila-oidc` library.

## `nila_jwt_proxy`

This example showcases a simple HTTP proxy built with Pingora that uses `nila-oidc` to validate JWT Bearer tokens from the `Authorization` header. It's named `nila_jwt_proxy` to reflect its use of the Nila OIDC library.

### Configuration

The proxy's behavior is configured via the `examples/proxy_config.yaml` file. You'll need to customize this file with your OIDC provider's details:

*   `issuer_url`: **Required.** The issuer URL of your OIDC provider (e.g., `https://accounts.google.com`).
*   `client_id`: **Required.** Your application's client ID, as registered with the OIDC provider. This is crucial for validating the `aud` (audience) claim in the token.
*   `jwks_uri` (Optional): You can uncomment and set this to directly specify the JWKS endpoint, bypassing OIDC discovery.
*   `algorithms` (Optional): A list of JWT signing algorithms to accept (e.g., `["RS256"]`). Defaults to `["RS256"]` if not specified.
*   `leeway_seconds` (Optional): Clock skew tolerance in seconds. Defaults to 60.
*   `listen_addr`: The address and port the proxy will listen on (e.g., `0.0.0.0:6188`).
*   `upstream_addr`: The address and port of the upstream service the proxy will forward valid requests to (e.g., `1.1.1.1:80`).

**Example `proxy_config.yaml`:**
```yaml
issuer_url: "https://accounts.google.com"
client_id: "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com" # <-- IMPORTANT: Replace this!
# jwks_uri: "https://www.googleapis.com/oauth2/v3/certs"
algorithms:
  - "RS256"
leeway_seconds: 60
listen_addr: "0.0.0.0:6188"
upstream_addr: "httpbin.org:80" # A public test upstream
```

### Running the Example

1.  **Ensure Pingora Dependencies:**
    Your main `Cargo.toml` should correctly reference Pingora crates (e.g., via `git` or `path` as they are not on crates.io).

2.  **Build and Run:**
    Navigate to the root of the `nila-oidc` project and run:
    ```bash
    cargo run --example nila_jwt_proxy
    ```
    The proxy will start listening on the address specified in `proxy_config.yaml`.

3.  **Testing:**
    You'll need a valid JWT (ID Token) from your configured OIDC provider.
    ```bash
    # Replace <YOUR_JWT_TOKEN> with an actual token
    curl -v -H "Authorization: Bearer <YOUR_JWT_TOKEN>" http://localhost:6188/get

    # Test without a token (should result in 401)
    curl -v http://localhost:6188/get

    # Test with an invalid token (should result in 401)
    curl -v -H "Authorization: Bearer aninvalidtoken" http://localhost:6188/get
    ```
    If the token is valid, the request will be proxied to the `upstream_addr`. Otherwise, a 401 Unauthorized response will be returned.

### Notes
*   The example currently passes `None` for nonce validation (`validator.validate::<Claims>(token, None).await`). In a complete OIDC Authorization Code Flow, you would generate a nonce, store it, and pass the stored nonce here for validation against the `nonce` claim in the ID Token. For simple bearer token validation where the token is obtained through other means (e.g., client credentials), nonce validation might not be applicable or might be handled differently.
*   The upstream SNI in the example is derived simply from the host part of `upstream_addr`. A more sophisticated proxy might obtain SNI from the original request's Host header or have it explicitly configured if the upstream is TLS-enabled. The example currently sets `tls: false` for the upstream.