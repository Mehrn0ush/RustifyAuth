use crate::core::authorization::AuthorizationCodeFlow;
use crate::core::extension_grants::{CustomGrant, DeviceFlowHandler, ExtensionGrantHandler};
use crate::core::pkce::validate_pkce_challenge;
use crate::core::token::{extract_tbid, TokenGenerator, TokenRevocation};
use crate::core::types::{TokenError, TokenRequest, TokenResponse};
use crate::endpoints::revoke::RevokeTokenRequest;
use crate::security::rate_limit::RateLimiter;
use crate::storage::memory::TokenStore;
use actix_web::{web, HttpRequest, HttpResponse, ResponseError, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
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
            TokenError::InvalidSignature => HttpResponse::Unauthorized().body("Invalid signature"),
            TokenError::ExpiredToken => HttpResponse::Unauthorized().body("Expired token"),
            TokenError::InsufficientScope => HttpResponse::Forbidden().body("Insufficient scope"),
            TokenError::InvalidClient => HttpResponse::Unauthorized().body("Invalid client"),
            TokenError::UnsupportedOperation => {
                HttpResponse::BadRequest().body("Unsupported operation")
            }
            TokenError::InvalidTokenBinding => {
                HttpResponse::Unauthorized().body("Invalid Token Binding")
            }
            TokenError::MissingTokenBinding => {
                HttpResponse::BadRequest().body("Missing Token Binding")
            }
            _ => HttpResponse::InternalServerError().body("Unknown error"),
        }
    }
}

// Token endpoint supporting authorization code, extension grants, and device flow
pub async fn token_endpoint(
    req: HttpRequest,
    form: web::Form<TokenRequest>,
    token_generator: Arc<dyn TokenGenerator>,
    token_store: Arc<dyn TokenStore>,
    rate_limiter: Arc<RateLimiter>, // Rate limiter to protect from abuse
    auth_code_flow: Option<Arc<Mutex<AuthorizationCodeFlow>>>, // Optional for authorization code flow
    device_flow_handler: Option<Arc<dyn DeviceFlowHandler>>,   // Optional for device flow
    extension_grant_handler: Option<Arc<dyn ExtensionGrantHandler>>, // Optional for extension grant handler
) -> Result<HttpResponse, TokenError> {
    let tbid = extract_tbid(&req)?;

    // Check rate-limiting before proceeding
    if rate_limiter.is_rate_limited(&form.client_id) {
        return Err(TokenError::RateLimited);
    }

    match form.grant_type.as_str() {
        // Handle Authorization Code Flow
        "authorization_code" => {
            if let Some(auth_flow) = auth_code_flow {
                handle_authorization_code_flow(&form, auth_flow).await
            } else {
                Err(TokenError::UnsupportedGrantType)
            }
        }

        "refresh_token" => {
            let refresh_token = form.refresh_token.as_ref().unwrap();
            let scope = form.scope.as_deref().unwrap_or("default_scope");

            let (access_token, new_refresh_token) = token_generator.exchange_refresh_token(
                refresh_token,
                &form.client_id,
                scope,
                Some(tbid.clone()),
            )?;

            Ok(HttpResponse::Ok().json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: token_generator.access_token_lifetime().as_secs(),
                refresh_token: new_refresh_token,
                scope: Some(scope.to_string()),
            }))
        }

        "client_credentials" => {
            let scope = form.scope.as_deref().unwrap_or("default_scope");

            let access_token = token_generator.generate_access_token(
                &form.client_id,
                "client_credentials_user",
                scope,
                Some(tbid.clone()),
            )?;

            Ok(HttpResponse::Ok().json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: token_generator.access_token_lifetime().as_secs(),
                refresh_token: "".to_string(), // No refresh token for client_credentials flow
                scope: Some(scope.to_string()),
            }))
        }

        "urn:ietf:params:oauth:grant-type:device_code" => {
            if let Some(device_handler) = device_flow_handler {
                handle_device_code_flow(&form, device_handler).await
            } else {
                Err(TokenError::UnsupportedGrantType)
            }
        }

        "urn:ietf:params:oauth:grant-type:custom-grant" => {
            if let Some(extension_handler) = extension_grant_handler {
                handle_extension_grant_flow(&form, extension_handler).await
            } else {
                Err(TokenError::UnsupportedGrantType)
            }
        }

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

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub scope: Option<String>,
    pub aud: Option<String>,
    pub client_id: Option<String>,
    pub iat: u64,
    pub iss: Option<String>,
}
// Token revocation endpoint handler
pub async fn revoke_token_endpoint(
    req: HttpRequest,
    form: web::Form<RevokeTokenRequest>,
    token_store: Arc<Mutex<dyn TokenStore>>,
) -> Result<HttpResponse, TokenError> {
    // Pass the full HttpRequest instead of req.head()
    let tbid = extract_tbid(&req)?;

    // Lock the token store to allow safe modification
    let mut token_store = token_store.lock().map_err(|_| TokenError::InternalError)?;

    // Extract token from Authorization header
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.replace("Bearer ", ""))
        .ok_or(TokenError::MissingFields)?;

    // Revoke the token using the appropriate method from `TokenRevocation`
    if form.token_type_hint.as_deref() == Some("refresh_token") {
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
