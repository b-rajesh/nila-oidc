use crate::types::Base64UrlEncodedBytes;
use crate::{JsonWebKey, SignatureVerificationError};

use super::{jwk::CoreJsonCurveType, CoreJsonWebKey};
use crate::core::jwk::CoreJsonWebKeyType;

use rsa::signature::Verifier;
use sha2::Digest;

fn rsa_public_key(
    key: &CoreJsonWebKey,
) -> Result<(&Base64UrlEncodedBytes, &Base64UrlEncodedBytes), String> {
    if *key.key_type() != CoreJsonWebKeyType::RSA {
        Err("RSA key required".to_string())
    } else {
        let n = key
            .n
            .as_ref()
            .ok_or_else(|| "RSA modulus `n` is missing".to_string())?;
        let e = key
            .e
            .as_ref()
            .ok_or_else(|| "RSA exponent `e` is missing".to_string())?;
        Ok((n, e))
    }
}

fn ec_public_key(
    key: &CoreJsonWebKey,
) -> Result<
    (
        &Base64UrlEncodedBytes,
        &Base64UrlEncodedBytes,
        &CoreJsonCurveType,
    ),
    String,
> {
    if *key.key_type() != CoreJsonWebKeyType::EllipticCurve {
        Err("EC key required".to_string())
    } else {
        let x = key
            .x
            .as_ref()
            .ok_or_else(|| "EC `x` part is missing".to_string())?;
        let y = key
            .y
            .as_ref()
            .ok_or_else(|| "EC `y` part is missing".to_string())?;
        let crv = key
            .crv
            .as_ref()
            .ok_or_else(|| "EC `crv` part is missing".to_string())?;
        Ok((x, y, crv))
    }
}

pub fn verify_rsa_signature_pkcs1v15<D>(
    key: &CoreJsonWebKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError>
where
    D: Digest + const_oid::AssociatedOid,
{
    let (n, e) = rsa_public_key(key).map_err(SignatureVerificationError::InvalidKey)?;
    // let's n and e as a big integers to prevent issues with leading zeros
    // according to https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1
    // `n` is always unsigned (hence has sign plus)

    let n_bigint = rsa::BigUint::from_bytes_be(n.as_ref());
    let e_bigint = rsa::BigUint::from_bytes_be(e.as_ref());
    let public_key = rsa::RsaPublicKey::new(n_bigint, e_bigint)
        .map_err(|e| SignatureVerificationError::InvalidKey(e.to_string()))?;

    let verifying_key = rsa::pkcs1v15::VerifyingKey::<D>::new(public_key);
    let signature = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| SignatureVerificationError::CryptoError("Invalid signature format".to_string()))?;
    
    verifying_key
        .verify(msg, &signature)
        .map_err(|_| SignatureVerificationError::CryptoError("bad signature".to_string()))
}

pub fn verify_rsa_signature_pss<D>(
    key: &CoreJsonWebKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError>
where
    D: Digest + sha2::digest::FixedOutputReset,
{
    let (n, e) = rsa_public_key(key).map_err(SignatureVerificationError::InvalidKey)?;
    // let's n and e as a big integers to prevent issues with leading zeros
    // according to https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1
    // `n` is always unsigned (hence has sign plus)

    let n_bigint = rsa::BigUint::from_bytes_be(n.as_ref());
    let e_bigint = rsa::BigUint::from_bytes_be(e.as_ref());
    let public_key = rsa::RsaPublicKey::new(n_bigint, e_bigint)
        .map_err(|e| SignatureVerificationError::InvalidKey(e.to_string()))?;

    let verifying_key = rsa::pss::VerifyingKey::<D>::new(public_key);
    let signature = rsa::pss::Signature::try_from(signature)
        .map_err(|_| SignatureVerificationError::CryptoError("Invalid signature format".to_string()))?;
    
    verifying_key
        .verify(msg, &signature)
        .map_err(|_| SignatureVerificationError::CryptoError("bad signature".to_string()))
}
/// According to RFC5480, Section-2.2 implementations of Elliptic Curve Cryptography MUST support the uncompressed form.
/// The first octet of the octet string indicates whether the uncompressed or compressed form is used. For the uncompressed
/// form, the first octet has to be 0x04.
/// According to https://briansmith.org/rustdoc/ring/signature/index.html#ecdsa__fixed-details-fixed-length-pkcs11-style-ecdsa-signatures,
/// to recover the X and Y coordinates from an octet string, the Octet-String-To-Elliptic-Curve-Point Conversion
/// is used (Section 2.3.4 of https://www.secg.org/sec1-v2.pdf).
pub fn verify_ec_signature(
    key: &CoreJsonWebKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError> {
    use p384::ecdsa::signature::Verifier;

    let (x, y, crv) = ec_public_key(key).map_err(SignatureVerificationError::InvalidKey)?;
    let mut pk = vec![0x04];
    pk.extend_from_slice(x.as_ref());
    pk.extend_from_slice(y.as_ref());
    match *crv {
        CoreJsonCurveType::P256 => {
            let public_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk)
                .map_err(|e| SignatureVerificationError::InvalidKey(e.to_string()))?;
            public_key
                .verify(
                    msg,
                    &p256::ecdsa::Signature::from_bytes(signature.into()).map_err(|_| {
                        SignatureVerificationError::CryptoError("Invalid signature".to_string())
                    })?,
                )
                .map_err(|_| {
                    SignatureVerificationError::CryptoError("EC Signature was wrong".to_string())
                })
        }
        CoreJsonCurveType::P384 => {
            let public_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&pk)
                .map_err(|e| SignatureVerificationError::InvalidKey(e.to_string()))?;
            public_key
                .verify(
                    msg,
                    &p384::ecdsa::Signature::from_bytes(signature.into()).map_err(|_| {
                        SignatureVerificationError::CryptoError("Invalid signature".to_string())
                    })?,
                )
                .map_err(|_| {
                    SignatureVerificationError::CryptoError("EC Signature was wrong".to_string())
                })
        }
        CoreJsonCurveType::P521 => Err(SignatureVerificationError::UnsupportedAlg(
            "P521".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    use crate::core::CoreJsonWebKey;

    #[test]
    fn test_leading_zeros_are_parsed_correctly() {
        // The message we signed
        let msg = "THIS IS A SIGNATURE TEST";
        let signature = base64::decode("bg0ohqKwYHAiODeG6qkJ-6IhodN7LGPxAh4hbWeIoBdSXrXMt8Ft8U0BV7vANPvF56h20XB9C0021x2kt7iAbMgPNcZ7LCuXMPPq04DrBpMHafH5BXBwnyDKJKrzDm5sfr6OgEkcxSLHaSJ6gTWQ3waPt6_SeH2-Fi74rg13MHyX-0iqz7bZveoBbGIs5yQCwvXgrDS9zW5LUwUHozHfE6FuSi_Z92ioXeu7FHHDg1KFfg3hs8ZLx4wAX15Vw2GCQOzvyNdbItxXRLnrN1NPqxFquVNo5RGlx6ihR1Jfe7y_n0NSR2q2TuU4cIwR0LRwEaANy5SDqtleQPrTEn8nGQ").unwrap();
        // RSA pub key with leading 0
        let key : CoreJsonWebKey = serde_json::from_value(serde_json::json!(
            {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "TEST_KEY_ID",
            "alg": "RS256",
            "n": "AN0M6Y760b9Ok2PxDOps1TgSmiOaR9mLIfUHtZ_o-6JypOckGcl1CxrteyokOb3WyDsfIAN9fFNrycv5YoLKO7sh0IcfzNEXFgzK84HTBcGuqhN8NV98Z6N9EryUrgJYsJeVoPYm0MzkDe4NyWHhnq-9OyNCQzVELH0NhhViQqRyM92OPrJcQlk8s3ZvcgRmkd-rEtRua8SbS3GEvfvgweVy5-qcJCGoziKfx-IteMOm6yKoHvqisKb91N-qw_kSS4YQUx-DZVDo2g24F7VIbcYzJGUOU674HUF1j-wJyXzG3VV8lAXD8hABs5Lh87gr8_hIZD5gbYBJRObJk9XZbfk"
            }
        )).unwrap();

        let mut hasher = sha2::Sha256::new();
        hasher.update(msg);
        let hash = hasher.finalize().to_vec();
        assert! {
            verify_rsa_signature_pkcs1v15::<sha2::Sha256>(
                &key,
                &hash,
                &signature,
            ).is_ok()
        }
    }
}