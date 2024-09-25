use crate::core::token::Claims;
use crate::error::OAuthError;
use dotenv::dotenv;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/*
#[derive(Serialize)]
struct Claims {
    sub: String,        // The subject (client ID)
    scope: Vec<String>, // Scopes for this token
    exp: usize,         // Expiration timestamp
}
*/
/// Generates a JWT for the client credentials flow.
///
/// # Arguments
/// * `client_id` - The ID of the client (subject of the token).
/// * `scopes` - The scopes that are granted to the client.
/// * `now` - Current time as a `SystemTime`.
/// * `expiry_duration` - The duration for which the token is valid.
///
/// # Returns
/// A `Result<String, OAuthError>` containing the JWT if successful, or an error otherwise.
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
        iss: Some("your_issuer".to_string()),
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
