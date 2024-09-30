use crate::core::token::Claims;
use crate::core::types::TokenError;
use crate::error::OAuthError;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5}; // Using Dilithium PQC implementation
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::SignedMessage;
use rustls::PrivateKey;
use rustls_pemfile::private_key;
use serde::Serialize;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Generates a JWT using the specified signing algorithm.
pub fn generate_jwt(
    claims: Claims,
    signing_algorithm: SigningAlgorithm,
) -> Result<String, OAuthError> {
    match signing_algorithm {
        SigningAlgorithm::RSA => sign_with_rsa(&claims),
        SigningAlgorithm::ECC => sign_with_ecc(&claims),
        SigningAlgorithm::Dilithium => sign_with_dilithium(&claims),
        SigningAlgorithm::Falcon => sign_with_falcon(&claims),
    }
}

pub enum SigningAlgorithm {
    RSA,
    ECC,
    Dilithium,
    Falcon,
}

pub fn sign_token_with_algorithm(
    claims: &Claims,
    algorithm: SigningAlgorithm,
    private_key: &[u8],
) -> Result<String, OAuthError> {
    match algorithm {
        SigningAlgorithm::RSA => sign_with_rsa(claims),
        SigningAlgorithm::ECC => sign_with_ecc(claims),
        SigningAlgorithm::Dilithium => sign_with_dilithium(claims),
        SigningAlgorithm::Falcon => sign_with_falcon(claims),
    }
}

// Sign JWT using RS256 (existing RSA signing)
pub fn sign_with_rsa(claims: &Claims) -> Result<String, OAuthError> {
    let private_key_pem = env::var("JWT_PRIVATE_KEY").map_err(|_| {
        OAuthError::InternalError("JWT_PRIVATE_KEY not set in environment".to_string())
    })?;
    let private_key = private_key_pem.as_bytes();
    encode(
        &Header::new(Algorithm::RS256),
        claims,
        &EncodingKey::from_rsa_pem(private_key).map_err(|_| OAuthError::TokenGenerationError)?,
    )
    .map_err(|_| OAuthError::TokenGenerationError)
}

// Example: Dilithium signature (use actual signature scheme in practice)
fn sign_with_dilithium(claims: &Claims) -> Result<String, OAuthError> {
    let (_public_key, secret_key) = dilithium2::keypair();
    let message = serde_json::to_vec(&claims).map_err(|_| OAuthError::TokenGenerationError)?;
    let signed_message = dilithium2::sign(&message, &secret_key);
    Ok(base64::encode(signed_message.as_bytes())) // Return the base64 encoded signature
}

// Example: Falcon signature
fn sign_with_falcon(claims: &Claims) -> Result<String, OAuthError> {
    let (_public_key, secret_key) = falcon1024::keypair();
    let message = serde_json::to_vec(&claims).map_err(|_| OAuthError::TokenGenerationError)?;
    let signed_message = falcon1024::sign(&message, &secret_key);
    Ok(base64::encode(signed_message.as_bytes())) // Return the base64 encoded signature
}

// Placeholder ECC signing function (this would be similar to RSA)
fn sign_with_ecc(claims: &Claims) -> Result<String, OAuthError> {
    // ECC logic here
    Ok("ecc_signature_placeholder".to_string())
}

pub fn get_signing_algorithm() -> SigningAlgorithm {
    match env::var("JWT_SIGNING_ALGORITHM").as_deref() {
        Ok("RSA") => SigningAlgorithm::RSA,
        Ok("ECC") => SigningAlgorithm::ECC,
        Ok("Falcon") => SigningAlgorithm::Falcon,
        _ => SigningAlgorithm::Dilithium, // Default to Dilithium if not specified
    }
}
///////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_signing_dilithium() {
        let claims = Claims {
            sub: "client_id".to_string(),
            exp: 1234567890,
            scope: Some("read write".to_string()),
            aud: None,
            client_id: None,
            iat: 1234567890,
            iss: Some("issuer".to_string()),
            tbid: None,
        };
        let token = sign_with_dilithium(&claims).expect("Failed to sign with Dilithium");
        assert!(!token.is_empty());
    }

    #[test]
    fn test_jwt_signing_falcon() {
        let claims = Claims {
            sub: "client_id".to_string(),
            exp: 1234567890,
            scope: Some("read write".to_string()),
            aud: None,
            client_id: None,
            iat: 1234567890,
            iss: Some("issuer".to_string()),
            tbid: None,
        };
        let token = sign_with_falcon(&claims).expect("Failed to sign with Falcon");
        assert!(!token.is_empty());
    }
}
