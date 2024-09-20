use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use serde::{Serialize};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use crate::error::OAuthError;

#[derive(Serialize)]
struct Claims {
    sub: String,        // The subject (client ID)
    scope: Vec<String>, // Scopes for this token
    exp: usize,         // Expiration timestamp
}

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
    expiry_duration: Duration
) -> Result<String, OAuthError> {
    // Convert `SystemTime` to UNIX timestamp
    let now_unix = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let exp_unix = (now + expiry_duration).duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Create the claims (data to include in the JWT)
    let claims = Claims {
        sub: client_id,
        scope: scopes.into_iter().map(|s| s.to_string()).collect(), // Convert Vec<&str> to Vec<String>
        exp: exp_unix as usize,
    };

    // Load the RSA private key from a file (this should be stored securely)
    let private_key = include_bytes!("private_key.pem");

    // Encode the JWT using RS256 algorithm, mapping any potential errors to `OAuthError::TokenGenerationError`
    let token = encode(
        &Header::new(Algorithm::RS256), 
        &claims, 
        &EncodingKey::from_rsa_pem(private_key).map_err(|_| OAuthError::TokenGenerationError)? // Map potential error loading the key
    ).map_err(|_| OAuthError::TokenGenerationError)?; // Map error from JWT encoding to OAuthError

    Ok(token)  // Return the generated token
}
