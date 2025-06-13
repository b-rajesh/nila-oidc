// in tests/integration_test.rs

#[cfg(test)]
mod tests {
    use nila_oidc::prelude::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use serde_json::json;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::Duration;

    // Helper to create a dummy RSA key for signing tokens in tests.
    fn create_test_keys() -> (EncodingKey, serde_json::Value) {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let components = key.to_components();
        let encoding_key = EncodingKey::from_rsa_der(&key.to_pkcs1_der().unwrap()).unwrap();
        let jwk = json!({
            "kty": "RSA",
            "kid": "test-kid-1",
            "alg": "RS256",
            "n": base64_url::encode(&components.n.to_bytes_be()),
            "e": base64_url::encode(&components.e.to_bytes_be()),
        });
        (encoding_key, jwk)
    }

    #[tokio::test]
    async fn test_validator_happy_path_with_discovery() {
        // 1. Arrange: Set up the mock server.
        let mock_server = MockServer::start().await;
        let (encoding_key, jwk) = create_test_keys();
        let jwks = json!({ "keys": [jwk] });

        // Mock the OIDC discovery endpoint.
        let discovery_path = "/.well-known/openid-configuration";
        Mock::given(method("GET"))
           .and(path(discovery_path))
           .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/.well-known/jwks.json", mock_server.uri()),
            })))
           .mount(&mock_server)
           .await;

        // Mock the JWKS endpoint.
        Mock::given(method("GET"))
           .and(path("/.well-known/jwks.json"))
           .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
           .expect(1) // Expect this to be called exactly once.
           .mount(&mock_server)
           .await;

        // 2. Act: Configure and use the validator.
        let config = ConfigBuilder::new()
           .issuer_url(&mock_server.uri())
           .unwrap()
           .client_id("test-client".to_string())
           .build()
           .unwrap();

        let validator = Validator::new(config);

        // Create a valid token.
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid-1".to_string());
        let claims = json!({
            "iss": mock_server.uri(),
            "sub": "user123",
            "aud": "test-client",
            "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            "iat": chrono::Utc::now().timestamp(),
        });
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // Validate the token.
        let result = validator.validate(&token, None).await;

        // 3. Assert
        assert!(result.is_ok());
        let token_data = result.unwrap();
        assert_eq!(token_data.claims.sub, "user123");
        
        // The mock server will automatically verify the `.expect(1)` on drop.
    }
}