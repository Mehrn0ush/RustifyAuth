use actix_web::{web, HttpResponse};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::oidc::claims::Claims; // Ensure this imports the right Claims struct
use crate::oidc::discovery::{fetch_discovery_document, DiscoveryDocument}; // Import DiscoveryDocument

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct GoogleIdTokenClaims {
    pub sub: String, // Subject (user ID)
    pub email: String,
    pub exp: usize,  // Expiration time as usize
    pub aud: String, // Audience
    pub iss: String, // Issuer
}

/// Validates the Google ID token
pub async fn validate_google_id_token(
    id_token: &str,
    client: &Client,
) -> Result<Claims, Box<dyn Error>> {
    // Fetch the discovery document to get the JWKS URI
    let discovery_doc = fetch_discovery_document(client).await?;

    // Validate the ID token with the corresponding claims
    let claims: GoogleIdTokenClaims =
        decode_and_validate_id_token(id_token, &discovery_doc).await?;

    // Optionally, further validate the claims
    validate_google_claims(&claims)?;

    Ok(Claims {
        sub: claims.sub,
        exp: claims.exp, // Keep as usize
        aud: claims.aud,
        iss: claims.iss,
        // Set other fields if necessary, ensure these are compatible
        ..Default::default()
    })
}

/// Decodes and validates the ID token against the public keys
async fn decode_and_validate_id_token(
    id_token: &str,
    discovery_doc: &DiscoveryDocument,
) -> Result<GoogleIdTokenClaims, Box<dyn Error>> {
    // Logic for decoding the ID token using the public keys
    // Placeholder for your JWT validation logic

    // Example structure to represent decoded claims
    let claims: GoogleIdTokenClaims = serde_json::from_str(id_token) // This should be a proper JWT decoding
        .map_err(|_| "Failed to decode ID token")?;

    // Check claims based on the discovery document (e.g., validate audience and issuer)
    if claims.aud != discovery_doc.issuer {
        return Err(Box::from("Invalid audience"));
    }
    if claims.iss != discovery_doc.issuer {
        return Err(Box::from("Invalid issuer"));
    }

    Ok(claims)
}

/// Validates the Google claims
pub fn validate_google_claims(claims: &GoogleIdTokenClaims) -> Result<(), String> {
    if claims.exp <= chrono::Utc::now().timestamp() as usize {
        return Err("ID token has expired".into());
    }
    // Add more validation logic as necessary
    Ok(())
}

/// Handler to validate Google ID token from a request
pub async fn validate_google_token_handler(
    query: web::Query<String>,
    client: web::Data<Client>,
) -> HttpResponse {
    match validate_google_id_token(&query.into_inner(), &client).await {
        Ok(_) => HttpResponse::Ok().body("Token is valid"),
        Err(err) => HttpResponse::BadRequest().body(format!("Validation error: {}", err)),
    }
}
