use nila_oidc::prelude::*;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use url::Url;
use uuid::Uuid;
use jsonwebtoken::{encode, Header, EncodingKey};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::pkcs1::EncodeRsaPrivateKey;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper function to create a temporary PKCS#8 RSA private key file for testing.
fn create_temp_rsa_key() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("test_private_key.pem");
    let mut key_file = File::create(&key_path).unwrap();
    
    // A sample 2048-bit PKCS#8 RSA private key for testing.
    let private_key_pem = r#"
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDCxoFcIEONPshI
t7Om4jaXWDwTo4iNB2cUVoauADr7TtizjiZ/s1omovmc4OnldEHmUakJ6eWXnyCc
EDq1RqbwRD8yHyFTK4jBHKEQhwl69T9251EU8d+yrjCsovdf7BZL20aCWLYp5mNW
lINZiqI4nHZ8aSkErTxx50+/FW7UF2Ppn+9f8ov+pRH5+nJNCUYaE97XpZ0lMLKm
gEuWDWi6J6yY6N3GawQEct5Y6OOO7d35Ax66V1++LbVkAcOpwU5iMbFHf0LuQNMa
oKvn9NhwithEz/HzsRvPsdYdwFddGRVwC7wzNgjhiTjyvuBV+z/K/vMe7LtX1UIy
m5Qv/Rn1AgMBAAECggEADIqTO2yDvP1XuxWXq+gGmNcgbdP1T74JcpihrQ7XErsV
yUtJX6abkupNL+nsKuSXS65it9Xc0oGiAWUqyo+lNx+bLBiEtky9ePsQGeGACEVF
/rDP7+J6bhBjkkd0rd355OIrwj/WYZCeloK93w7wpBGFsDwQh+cPAcyMPiMHUwDz
kCkEuU0OmaU3qydKbcWAJ1y/inn1vxSftdF6GC9JrN4xTTy+L9+WrJJ4FB12tCE+
eOSMct/1DxkgLcOvgzRT7wzqVBpmP6Rjk0zzCvdRloUIGzMyCf4/1MVTam4wFXSX
vQTST+srjBGe+H8lhXYTQdWxNBOCQdJ8kNRbuoOIQQKBgQD9ykDSaVDGSX/vve0l
Nl6/oFS5D71aed0XF3ApScrCeiaRnkvEn6aMmzR5AAReGmyxphBatMPTSmWNwUMD
lXSv4Wzf0+S1XiOpfndvlCO4PtnuWTY9XWJi9EqVtn3ximREOQ6c+ewF6irQAatN
VqhAoMB8QzNhhNV70WQFW8Z1VQKBgQDEeLJ3CwI8sQVONw9B9nJaa5O3d28Trlj4
E+4i0u+JFzG9MZgwW/Ro7CRXQe2U5iUlmh5F1Mvr4Fo94vVFrBrs5p2lPDEauuAC
GuFqrmjbpsTdfW7cXMdbVt5/0vm6r5xJTmmKzNmRxPm+GXFIHnXOQ36D2tdzhsch
P4q8yogSIQKBgDCIni7e7xCMe8foRVKpfCMfUTR22xpTVcGVvOBYeUsJuxh78jdu
5JXdFILTSwKIASNUA6qlCRH+Fz+tptgnm8IK1RxU1FcO4rkGM2cGKHKSqnCXZPUF
R8xutVi+JoWrlpMpai8A6G8VIgzXVOAcY17Any7kVw4eLglYuM0BiQllAoGAZw7M
xmbu6HkOyGVXSomEmGt/k6hBirhUkOSbcIbnASk6fPxr0Uoa3YKo2WCKyCUk7SF3
qbeis/r+OyI2+DH7+bJKlScKtvO5l0EUZwpPlJBZCbnHEi5UoFPj6Hb5afS97TIF
aLplkfIZ8p6T7nmT3/tFfNKpWz8iaw1S8A8o6yECgYAO9GvTbT1ofOrnq0SPjqXf
VI6atDhn+Tg7FLopeuX5lkjN0314V3x9iiW3KAPxasEFWaWPy541CfrHtj2De8aD
epTFhRUsNQnXU+niF+aYDkZ2ozMWtRvUU5CIDCGNebMH2iKhwgedcz93SxSJUXjz
/GzHOJRQOqHvv5bs86SaZQ==
-----END PRIVATE KEY-----
"#;
    key_file
        .write_all(private_key_pem.trim().as_bytes())
        .unwrap();
    (dir, key_path)
}

#[tokio::test]
async fn test_token_generation_and_validation_end_to_end() {
    // --- 1. SETUP ---
    let (_temp_dir, key_path) = create_temp_rsa_key();

    let mut clients = HashMap::new();
    clients.insert(
        "test-client".to_string(),
        ClientDetails {
            client_secret: Some("test-secret".to_string()),
            allowed_scopes: Some("read write".to_string()),
            default_scopes: Some("read".to_string()),
        },
    );

    let generator_config = GeneratorConfig {
        issuer: Url::parse("https://id.test.local/").unwrap(),
        algorithm: Algorithm::RS256,
        clients,
        token_ttl_seconds: 60,
        signing_key: SigningKeyConfig::RsaPemFile(key_path),
        supported_scopes: Some("read write admin".to_string()),
        identity_nila_grant_type_extension: "http://id.nilaproxy.dev/oauth2/grant-type/api-key".to_string(),
    };
    let generator = Generator::new(generator_config).expect("Failed to create generator");

    // --- 2. GENERATE TOKEN ---
    let token = generator
        .issue_token("test-client", "test-secret", "client_credentials", None)
        .expect("Failed to issue token");

    // --- 3. SETUP MOCK JWKS ENDPOINT ---
    let jwks = generator
        .get_public_jwks()
        .expect("Generator should have a public JWKS");
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(&mock_server)
        .await;

    // --- 4. SETUP VALIDATOR WITH CLAIM ASSERTION ---
    // We will use `assert_claims` to explicitly validate the audience,
    // testing the new, more powerful validation feature.
    let mut claims_to_assert = HashMap::new();
    claims_to_assert.insert("aud".to_string(), serde_json::json!("test-client"));

    let validator_config = ConfigBuilder::new()
        .issuer_url("https://id.test.local/")
        .unwrap()
        .jwks_uri(
            Url::parse(&mock_server.uri())
                .unwrap()
                .join("/.well-known/jwks.json")
                .unwrap()
                .as_ref(),
        )
        .unwrap()
        .algorithms(vec![Algorithm::RS256])
        .assert_claims(claims_to_assert)
        // Disable nonce validation for this test, as it's a client credentials flow.
        .validate_nonce(false)
        .build()
        .expect("Failed to build validator config");
    let validator = Validator::new(validator_config);

    // --- 5. VALIDATE TOKEN ---
    let token_data = validator
        .validate::<Claims>(&token, None)
        .await
        .expect("Token validation should succeed");

    // --- 6. ASSERTIONS ---
    assert_eq!(token_data.claims.iss, "https://id.test.local/");
    assert_eq!(token_data.claims.aud.as_deref(), Some("test-client"));
    assert_eq!(token_data.claims.sub, "test-client");
    assert!(Uuid::parse_str(&token_data.claims.jti).is_ok(), "JTI should be a valid UUID");
    println!(
        "✅ End-to-end test passed: Token generated, served via JWKS, and successfully validated."
    );
}

#[test]
fn test_generator_invalid_client_credentials() {
    // --- SETUP ---
    let (_temp_dir, key_path) = create_temp_rsa_key();
    let mut clients = HashMap::new();
    clients.insert(
        "correct-client".to_string(),
        ClientDetails {
            client_secret: Some("correct-secret".to_string()),
            allowed_scopes: Some("read:all".to_string()),
            default_scopes: None,
        },
    );
    let generator_config = GeneratorConfig {
        issuer: Url::parse("https://id.test.local/").unwrap(),
        algorithm: Algorithm::RS256,
        clients,
        token_ttl_seconds: 60,
        signing_key: SigningKeyConfig::RsaPemFile(key_path),
        supported_scopes: Some("read:all write:all".to_string()),
        identity_nila_grant_type_extension: "http://id.nilaproxy.dev/oauth2/grant-type/api-key".to_string(),
    };
    let generator = Generator::new(generator_config).unwrap();

    // --- TEST CASES ---
    // Case 1: Wrong client_id
    let result_wrong_id = generator.issue_token("wrong-client", "correct-secret", "client_credentials", None);
    assert!(matches!(
        result_wrong_id,
        Err(NilaOidcError::InvalidClientCredentials)
    ));
    println!("✅ Correctly failed with wrong client ID.");

    // Case 2: Wrong client_secret
    let result_wrong_secret = generator.issue_token("correct-client", "wrong-secret", "client_credentials", None);
    assert!(matches!(
        result_wrong_secret,
        Err(NilaOidcError::InvalidClientCredentials)
    ));
    println!("✅ Correctly failed with wrong client secret.");

    // Case 3: Correct credentials
    let result_correct = generator.issue_token("correct-client", "correct-secret", "client_credentials", None);
    assert!(result_correct.is_ok());
    println!("✅ Correctly succeeded with valid credentials.");
}

#[test]
fn test_custom_grant_type_extension_flow() {
    // --- SETUP ---
    let (_temp_dir, key_path) = create_temp_rsa_key();
    let mut clients = HashMap::new();
    clients.insert(
        "extension-client".to_string(),
        ClientDetails {
            client_secret: None, // No secret configured
            allowed_scopes: Some("read:public admin:all".to_string()),
            default_scopes: Some("read:public".to_string()),
        },
    );

    let grant_type_extension = "http://id.nilaproxy.dev/oauth2/grant-type/api-key".to_string();

    let generator_config = GeneratorConfig {
        issuer: Url::parse("https://id.test.local/").unwrap(),
        algorithm: Algorithm::RS256,
        clients,
        token_ttl_seconds: 60,
        signing_key: SigningKeyConfig::RsaPemFile(key_path),
        supported_scopes: Some("read:public admin:all".to_string()),
        identity_nila_grant_type_extension: grant_type_extension.clone(),
    };
    let generator = Generator::new(generator_config).unwrap();

    // --- TEST CASES ---

    // Case 1: Request a token using the configured grant type extension. This should succeed.
    let result_api_key = generator.issue_token("extension-client", "", &grant_type_extension, Some("read:public"));
    assert!(
        result_api_key.is_ok(),
        "Client should be able to get a token with the custom grant type without a secret"
    );
    println!("✅ Correctly issued token for client using grant type extension.");

    // Case 2: Attempt to use the 'client_credentials' grant for this client. It should fail.
    let result_cc_fails = generator.issue_token("extension-client", "", "client_credentials", Some("read:public"));
    assert!(
        matches!(result_cc_fails, Err(NilaOidcError::InvalidClientCredentials)),
        "Client credentials grant should fail for a client with no configured secret"
    );
    println!("✅ Correctly rejected 'client_credentials' grant for client with no secret.");

    // Case 3: Attempt to use an unsupported grant type. It should fail.
    let result_unsupported_grant = generator.issue_token("extension-client", "", "unsupported_grant", Some("read:public"));
    assert!(
        matches!(result_unsupported_grant, Err(NilaOidcError::UnsupportedGrantType(_))),
        "An unsupported grant type should be rejected"
    );
    println!("✅ Correctly rejected an unsupported grant type.");

    // Case 4: Request a scope that is not in the allowed list. It should fail.
    let result_invalid_scope = generator.issue_token("extension-client", "", &grant_type_extension, Some("read:all"));
    assert!(
        matches!(result_invalid_scope, Err(NilaOidcError::InvalidScope(_))),
        "A request for a non-allowed scope should be rejected"
    );
    println!("✅ Correctly rejected request for a non-allowed scope.");

    // Case 5: Request a valid subset of allowed scopes. It should succeed.
    let result_valid_subset = generator.issue_token("extension-client", "", &grant_type_extension, Some("read:public admin:all"));
    assert!(result_valid_subset.is_ok(), "A request for a valid subset of scopes should succeed");
    println!("✅ Correctly accepted request for a valid subset of scopes.");
}

#[tokio::test]
async fn test_audience_validation_is_optional() {
    // --- 1. SETUP: Manually create a token WITHOUT an 'aud' claim ---
    let (_temp_dir, key_path) = create_temp_rsa_key();
    let pem = std::fs::read_to_string(key_path).unwrap();
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
    let pkcs1_der = private_key.to_pkcs1_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(pkcs1_der.as_bytes());

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = serde_json::json!({
        "iss": "https://id.test.local/",
        "sub": "test-subject",
        "iat": now,
        "exp": now + 3600,
    });
    let mut header = Header::new(Algorithm::RS256);
    // The header must contain the 'kid' so the validator knows which key to use from the JWKS.
    header.kid = Some("test-kid-for-optional-aud".to_string());
    let token_without_aud = encode(&header, &payload, &encoding_key).unwrap();

    // --- 2. SETUP MOCK JWKS ENDPOINT ---
    let public_key = private_key.to_public_key();
    let n = base64_url::encode(&public_key.n().to_bytes_be());
    let e = base64_url::encode(&public_key.e().to_bytes_be());
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "n": n,
            "e": e,
            "alg": "RS256",
            "use": "sig",
            "kid": "test-kid-for-optional-aud"
        }]
    });
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(&mock_server)
        .await;

    // --- 3. TEST SUCCESS: Validator with NO audience configured ---
    let validator_config_no_aud = ConfigBuilder::new()
        .issuer_url("https://id.test.local/")
        .unwrap()
        .jwks_uri(Url::parse(&mock_server.uri()).unwrap().join("/.well-known/jwks.json").unwrap().as_ref())
        .unwrap()
        .validate_nonce(false)
        .build()
        .unwrap();
    let validator_no_aud = Validator::new(validator_config_no_aud);

    // We expect this to succeed because we haven't asked the validator to check for an audience.
    let validation_result_success = validator_no_aud.validate::<serde_json::Value>(&token_without_aud, None).await;
    assert!(validation_result_success.is_ok(), "Validation should succeed when no audience is configured for validation.");
    println!("✅ Correctly validated token without 'aud' when audience validation was not configured.");

    // --- 4. TEST FAILURE: Validator WITH an audience configured ---
    let mut claims_to_assert = HashMap::new();
    claims_to_assert.insert("aud".to_string(), serde_json::json!("expected-audience"));

    let validator_config_with_aud = ConfigBuilder::new()
        .issuer_url("https://id.test.local/")
        .unwrap()
        .jwks_uri(Url::parse(&mock_server.uri()).unwrap().join("/.well-known/jwks.json").unwrap().as_ref())
        .unwrap()
        .assert_claims(claims_to_assert) // This time, we require an audience.
        .validate_nonce(false)
        .build()
        .unwrap();
    let validator_with_aud = Validator::new(validator_config_with_aud);

    // We expect this to fail because the token is missing the 'aud' claim we are now requiring.
    let validation_result_failure = validator_with_aud.validate::<serde_json::Value>(&token_without_aud, None).await;
    assert!(matches!(validation_result_failure, Err(NilaOidcError::JwtValidation(e)) if *e.kind() == jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("aud".to_string())),
        "Validation should fail with MissingRequiredClaim('aud')"
    );
    println!("✅ Correctly rejected token without 'aud' when audience validation was configured.");
}
