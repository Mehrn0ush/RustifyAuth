use crate::core::authorization::AuthorizationCodeFlow;
use crate::core::extension_grants::CustomGrant;
use crate::core::extension_grants::DeviceFlowHandler;
use crate::core::extension_grants::ExtensionGrantHandler;
use crate::core::pkce::validate_pkce_challenge;
use crate::core::token::TokenRevocation;
use crate::core::types::{TokenError, TokenRequest, TokenResponse};
use crate::endpoints::revoke::RevokeTokenRequest;
use crate::security::rate_limit::RateLimiter;
use crate::storage::memory::TokenStore;
use actix_web::ResponseError;
use actix_web::{web, HttpResponse, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use std::sync::{Arc, Mutex};

// Error Display Implementation
impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ResponseError for TokenError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            TokenError::InvalidGrant => HttpResponse::BadRequest().body("Invalid grant"),
            TokenError::UnsupportedGrantType => {
                HttpResponse::BadRequest().body("Unsupported grant type")
            }
            TokenError::MissingFields => HttpResponse::BadRequest().body("Missing fields"),
            TokenError::RateLimited => HttpResponse::TooManyRequests().body("Rate limited"),
            TokenError::InternalError => HttpResponse::InternalServerError().body("Internal error"),
            _ => HttpResponse::InternalServerError().body("Unknown error"),
        }
    }
}

// Token endpoint supporting authorization code, extension grants, and device flow
pub async fn token_endpoint(
    req: web::Form<TokenRequest>,
    rate_limiter: Arc<RateLimiter>, // Rate limiter to protect from abuse
    auth_code_flow: Option<Arc<Mutex<AuthorizationCodeFlow>>>, // Optional for authorization code flow
    device_flow_handler: Option<Arc<dyn DeviceFlowHandler>>,   // Optional for device flow
    extension_grant_handler: Option<Arc<dyn ExtensionGrantHandler>>, // Optional for extension grant handler
) -> Result<HttpResponse, TokenError> {
    // Check rate-limiting before proceeding
    if rate_limiter.is_rate_limited(&req.client_id) {
        return Err(TokenError::RateLimited);
    }

    match req.grant_type.as_str() {
        // Handle Authorization Code Flow
        "authorization_code" => {
            if let Some(auth_flow) = auth_code_flow {
                handle_authorization_code_flow(&req, auth_flow).await
            } else {
                Err(TokenError::UnsupportedGrantType)
            }
        }
        // Handle Device Code Flow
        "urn:ietf:params:oauth:grant-type:device_code" => {
            if let Some(device_handler) = device_flow_handler {
                handle_device_code_flow(&req, device_handler).await
            } else {
                Err(TokenError::UnsupportedGrantType)
            }
        }
        // Handle Extension Grants
        "urn:ietf:params:oauth:grant-type:custom-grant" => {
            if let Some(extension_handler) = extension_grant_handler {
                handle_extension_grant_flow(&req, extension_handler).await
            } else {
                Err(TokenError::UnsupportedGrantType)
            }
        }
        // Unsupported grant type
        _ => Ok(HttpResponse::BadRequest().body("Unsupported grant type")),
    }
}

/// Authorization Code Flow handler
async fn handle_authorization_code_flow(
    req: &web::Form<TokenRequest>,
    auth_code_flow: Arc<Mutex<AuthorizationCodeFlow>>,
) -> Result<HttpResponse, TokenError> {
    // Validate required fields for Authorization Code Flow
    if req.code.as_deref().unwrap_or("").is_empty()
        || req.pkce_verifier.as_deref().unwrap_or("").is_empty()
    {
        return Err(TokenError::MissingFields);
    }

    // Lock the AuthorizationCodeFlow to get mutable access
    let mut auth_code_flow = auth_code_flow
        .lock()
        .map_err(|_| TokenError::InternalError)?;

    // Validate the authorization code and PKCE verifier
    match auth_code_flow.exchange_code_for_token(
        req.code.as_deref().unwrap_or(""),
        req.pkce_verifier.as_deref().unwrap_or(""),
    ) {
        Ok(token_response) => Ok(HttpResponse::Ok().json(token_response)),
        Err(_) => Err(TokenError::InvalidGrant),
    }
}

/// Device Code Flow handler
async fn handle_device_code_flow(
    req: &web::Form<TokenRequest>,
    device_flow_handler: Arc<dyn DeviceFlowHandler>,
) -> Result<HttpResponse, TokenError> {
    // Validate required fields for Device Flow
    if req.device_code.as_deref().unwrap_or("").is_empty() {
        return Err(TokenError::MissingFields);
    }

    // Poll the device code flow for authentication
    match device_flow_handler.poll_device_code(req.device_code.as_deref().unwrap_or("")) {
        Ok(token_response) => Ok(HttpResponse::Ok().json(token_response)),
        Err(e) => Err(e),
    }
}

/// Extension Grant Flow handler
async fn handle_extension_grant_flow(
    req: &web::Form<TokenRequest>,
    extension_grant_handler: Arc<dyn ExtensionGrantHandler>,
) -> Result<HttpResponse, TokenError> {
    // Handle the custom extension grant
    let params = req.extra_params.clone().unwrap_or_default();
    match extension_grant_handler.handle_extension_grant(&req.grant_type, &params) {
        Ok(token_response) => Ok(HttpResponse::Ok().json(token_response)),
        Err(e) => Err(e),
    }
}

/// Token signing logic
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
    req: web::Form<RevokeTokenRequest>,
    token_store: Arc<Mutex<dyn TokenStore>>, // Shared token store wrapped in Mutex
) -> Result<HttpResponse, TokenError> {
    // Lock the token store to allow safe modification
    let mut token_store = token_store.lock().map_err(|_| TokenError::InternalError)?;

    // Validate the token and client credentials
    let token = req.token.clone();

    // Revoke the token using the appropriate method from `TokenRevocation`
    if req.token_type_hint.as_deref() == Some("refresh_token") {
        if !token_store.revoke_refresh_token(&token) {
            return Err(TokenError::InvalidRequest); // Handle case where revocation fails
        }
    } else {
        // Revoke access token by default
        if !token_store.revoke_access_token(&token) {
            return Err(TokenError::InvalidRequest);
        }
    }

    Ok(HttpResponse::Ok().body("Token revoked"))
}
