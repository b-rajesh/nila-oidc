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
*   `identity_nila_op` (Optional): A section to configure the built-in OAuth2 token server (acting as an OpenID Provider) for the Client Credentials Grant.
    *   `issuer`: The `iss` claim value for generated tokens.
    *   `algorithm`: The algorithm to use for signing, e.g., "HS256" or "RS256".
    *   `token_ttl_seconds`: The lifetime of generated tokens in seconds.
    *   `signing_key`: The key material for signing. Use one of the nested options:
        *   `type`: Specifies the key type (`shared_secret` or `rsa_pem`).
        *   **Note:** If `rsa_pem` is used, the proxy will expose a JWKS endpoint at `GET /jwks` for public key discovery.
        *   `value`: The actual key material.
    *   `clients`: A map where each key is a `client_id` and the value contains its `client_secret` and optional `default_scopes`.
*   `listen_addr`: The address and port the proxy will listen on (e.g., `0.0.0.0:6188`).
*   `upstream_addr`: The address and port of the upstream service the proxy will forward valid requests to (e.g., `1.1.1.1:80`).

**Example `proxy_config.yaml`:**
```yaml
issuer_url: "https://accounts.google.com"
client_id: "your-client-id-for-validation" # <-- IMPORTANT: Replace this!
# jwks_uri: "https://www.googleapis.com/oauth2/v3/certs"
algorithms:
  - "RS256"
leeway_seconds: 60

identity_nila_op:
  issuer: "https://nila-oidc.dev"
  algorithm: "HS256"
  token_ttl_seconds: 3600
  signing_key:
    # Example for symmetric algorithms (HS256, HS384, HS512)
    type: shared_secret
    value: "a-very-secure-and-long-secret-for-hs256" # IMPORTANT: Use a strong, securely stored secret

    # If using 'rsa_pem' for signing, the proxy will expose a JWKS endpoint at /jwks
    # containing the public key for discovery by clients.
    # Example for asymmetric algorithms (RS256, RS384, RS512)
    # type: rsa_pem
    # value: |
    #   -----BEGIN RSA PRIVATE KEY-----
    #   ... your multi-line PEM-encoded private key here ...
    #   -----END RSA PRIVATE KEY-----
  clients:
    "my-test-client-id":
      client_secret: "my-test-client-secret"
      default_scopes: "read:all"

listen_addr: "0.0.0.0:6188"
upstream_addr: "httpbin.org:80" # A public test upstream
```

### Running the Example

1.  **Ensure Pingora Dependencies:** Your main `Cargo.toml` should correctly reference Pingora crates (e.g., via `git` or `path` as they are not on crates.io).

2.  **Generate an RSA Key (Optional):**
    If you want to use an asymmetric algorithm like `RS256` for the `token_generator`, you first need to generate a private key. You can use `openssl`:
    ```bash
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    ```
    Then, copy the entire content of `private_key.pem` and paste it into your `proxy_config.yaml` under the `rsa_pem` field, like so:
    ```yaml
    signing_key:
      rsa_pem: |
        -----BEGIN PRIVATE KEY-----
        ... (paste key content here) ...
        -----END PRIVATE KEY-----
    ```

3.  **Build and Run:**
    Navigate to the root of the `nila-oidc` project and run:
    ```bash
    cargo run --example nila_jwt_proxy
    ```
    The proxy will start listening on the address specified in `proxy_config.yaml`.

4.  **Testing:**
    You can test both the token generation and token validation features.

    #### Requesting an Access Token (Client Credentials Grant)
    Use the `client_id` and `client_secret` from the `identity_nila_op` section of your config to request a token from the `/token` endpoint.
    ```bash
    curl -X POST http://localhost:6188/token \
      -d "grant_type=client_credentials" \
      -d "client_id=my-test-client-id" \
      -d "client_secret=my-test-client-secret" \
      -d "scope=read:specific" # Optional: Request specific scopes
    ```
    The server will respond with a JSON object containing your `access_token`.

    #### Validating a Bearer Token
    You can use the `access_token` you just received to make a validated request to the proxy.
    ```bash
    # First, get the token and store it in a variable
    TOKEN=$(curl -s -X POST http://localhost:6188/token -d "grant_type=client_credentials" -d "client_id=my-test-client-id" -d "client_secret=my-test-client-secret" | jq -r .access_token)

    # Then, use the token in an Authorization header
    curl -v -H "Authorization: Bearer $TOKEN" http://localhost:6188/get

    # Test without a token (should result in 401)
    curl -v http://localhost:6188/get

    # Test with an invalid token (should result in 401)
    curl -v -H "Authorization: Bearer aninvalidtoken" http://localhost:6188/get
    ```
    If the token is valid, the request will be proxied to the `upstream_addr`. Otherwise, a 401 Unauthorized response will be returned.

    #### Discovering the JWKS Endpoint
    If `identity_nila_op.signing_key` is configured with `type: rsa_pem`, the proxy will expose its public key(s) in JWKS format at `/jwks`.
    ```bash
    curl http://localhost:6188/jwks
    ```

### Notes
*   The example currently passes `None` for nonce validation (`validator.validate::<Claims>(token, None).await`). In a complete OIDC Authorization Code Flow, you would generate a nonce, store it, and pass the stored nonce here for validation against the `nonce` claim in the ID Token. For simple bearer token validation where the token is obtained through other means (e.g., client credentials), nonce validation might not be applicable or might be handled differently.
*   The upstream SNI in the example is derived simply from the host part of `upstream_addr`. A more sophisticated proxy might obtain SNI from the original request's Host header or have it explicitly configured if the upstream is TLS-enabled. The example currently sets `tls: false` for the upstream.