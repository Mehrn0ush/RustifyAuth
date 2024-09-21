use crate::core::authorization::AuthorizationCodeFlow;
use crate::core::pkce::validate_pkce_challenge;
use crate::core::types::TokenError as AuthTokenError;
use crate::core::types::TokenRequest;
use crate::core::types::TokenResponse as AuthTokenResponse;
use crate::core::types::{TokenError, TokenResponse};
use crate::security::rate_limit::RateLimiter;
use crate::storage::memory::TokenStore;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

// Improved token error types

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for TokenError {}

// Improved token endpoint handler with PKCE validation and rate-limiting
pub async fn token_endpoint(
    req: TokenRequest,
    auth_code_flow: Arc<Mutex<AuthorizationCodeFlow>>, // Use Arc<Mutex<AuthorizationCodeFlow>>
    rate_limiter: Arc<RateLimiter>,                    // Rate limiter to protect from abuse
) -> Result<TokenResponse, TokenError> {
    // Input validation for empty or missing fields
    if req.code.as_deref().unwrap_or("").is_empty()
        || req.client_id.is_empty()
        || req.pkce_verifier.as_deref().unwrap_or("").is_empty()
    {
        return Err(TokenError::MissingFields);
    }

    // Check rate-limiting before proceeding
    if rate_limiter.is_rate_limited(&req.client_id) {
        return Err(TokenError::RateLimited);
    }

    // Lock the AuthorizationCodeFlow to get mutable access
    let mut auth_code_flow = auth_code_flow
        .lock()
        .map_err(|_| TokenError::InternalError)?;

    // Validate the authorization code and PKCE verifier
    match auth_code_flow.exchange_code_for_token(
        &req.code.as_deref().unwrap_or(""),
        &req.pkce_verifier.as_deref().unwrap_or(""),
    ) {
        Ok(token_response) => Ok(token_response),
        Err(_) => Err(TokenError::InvalidGrant),
    }
}

// Improved token signing logic with better error handling
pub fn sign_token(private_key: &[u8], payload: &Claims) -> Result<String, TokenError> {
    let header = Header::new(Algorithm::RS256);

    // Handle potential errors in loading the private key
    let encoding_key =
        EncodingKey::from_rsa_pem(private_key).map_err(|_| TokenError::InternalError)?;

    // Handle potential JWT encoding errors
    encode(&header, payload, &encoding_key).map_err(|_| TokenError::InternalError)
}

// Example Claims structure for JWT tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,       // Subject (user_id)
    client_id: String, // Client ID
    exp: usize,        // Expiration time (Unix timestamp)
    iat: usize,        // Issued at (Unix timestamp)
    iss: String,       // Issuer
}

// Token revocation endpoint handler
pub async fn revoke_token_endpoint(
    req: RevokeTokenRequest,
    token_store: Arc<Mutex<dyn TokenStore>>, // Shared token store wrapped in Mutex
) -> Result<(), TokenError> {
    // Lock the token store to allow safe modification
    let mut token_store = token_store.lock().map_err(|_| TokenError::InternalError)?;

    // Validate the token and client credentials
    let token = req.token;

    // Revoke the token using the appropriate method from `TokenRevocation`
    if let Some(token_type_hint) = req.token_type_hint.as_ref() {
        match token_type_hint.as_str() {
            "access_token" => {
                if !token_store.revoke_access_token(&token) {
                    return Err(TokenError::InvalidRequest); // Handle case where revocation fails
                }
            }
            "refresh_token" => {
                if !token_store.revoke_refresh_token(&token) {
                    return Err(TokenError::InvalidRequest); // Handle case where revocation fails
                }
            }
            _ => return Err(TokenError::InvalidRequest),
        }
    } else {
        // Handle revocation of tokens without a type hint
        if !token_store.revoke_access_token(&token) {
            return Err(TokenError::InvalidRequest); // Handle case where revocation fails
        }
    }

    Ok(())
}

// Request structure for token revocation
#[derive(Debug, Deserialize)]
pub struct RevokeTokenRequest {
    pub token: String,
    pub token_type_hint: Option<String>, // Optional hint for token type
}
