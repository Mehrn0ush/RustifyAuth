use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Option<String>,
}

// Token error types used across modules
#[derive(Debug, PartialEq)]
pub enum TokenError {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidPKCEChallenge,
    InternalError,
    InvalidToken,
    RateLimited,
    MissingFields,
    InvalidTokenTypeHint,
    InsufficientScope,
    ExpiredToken,
    InvalidSignature,
    UnsupportedOperation,
    InvalidTokenBinding,     
    MissingTokenBinding,     
}

// Define TokenRequest struct (adjust fields based on your OAuth 2.0 implementation)

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub pkce_verifier: Option<String>,
    pub device_code: Option<String>, // For device flow
    pub extra_params: Option<std::collections::HashMap<String, String>>, // For extension grants
}


// Define RegistrationError for RBAC
#[derive(Debug, PartialEq)]
pub enum RegistrationError {
    UnauthorizedClient,
    InvalidRequest,
    InvalidGrant,
}