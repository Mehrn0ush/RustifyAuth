use crate::core::token::Claims;
use crate::error::OAuthError;
use dotenv::dotenv;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn generate_jwt(
    client_id: String,
    scopes: Vec<&str>,
    now: SystemTime,
    expiry_duration: Duration,
) -> Result<String, OAuthError> {
    // Convert `SystemTime` to UNIX timestamp
    let now_unix = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let exp_unix = (now + expiry_duration)
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create the claims (data to include in the JWT)
    let claims = Claims {
        sub: client_id,
        exp: exp_unix,
        scope: Some(scopes.join(" ")),
        aud: None,
        client_id: None,
        iat: now_unix,
        iss: Some("your_issuer".to_string()), //
    };

    // Load the RSA private key from a file (this should be stored securely)
    //let private_key = include_bytes!("private_key.pem");
    let private_key =
        std::env::var("JWT_PRIVATE_KEY").map_err(|_| OAuthError::TokenGenerationError)?;

    // Encode the JWT using RS256 algorithm, mapping any potential errors to `OAuthError::TokenGenerationError`
    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(private_key.as_bytes())
            .map_err(|_| OAuthError::TokenGenerationError)?, // Map potential error loading the key
    )
    .map_err(|_| OAuthError::TokenGenerationError)?; // Map error from JWT encoding to OAuthError

    Ok(token) // Return the generated token
}
