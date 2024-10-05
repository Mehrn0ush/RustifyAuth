use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum TokenError {
    InvalidToken,
    TokenRevoked,
    // Add relevant errors for token revocation
}

#[derive(Debug, PartialEq)] // Add PartialEq here
pub enum OAuthError {
    InvalidClient,
    InvalidScope,
    TokenGenerationError,
    InvalidRequest,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    RateLimited,
    InternalError(String),
    InvalidCredentials,
    SessionNotFound,
    InvalidToken,
}

/// Struct representing an OAuth2 error response.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthErrorResponse {
    /// A single ASCII error code from a defined set.
    pub error: String,

    /// Human-readable text providing additional information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// A URI identifying a human-readable web page with information about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl OAuthErrorResponse {
    /// Helper function to create a new OAuthErrorResponse.
    pub fn new(error: &str, description: Option<&str>, uri: Option<&str>) -> Self {
        OAuthErrorResponse {
            error: error.to_string(),
            error_description: description.map(|s| s.to_string()),
            error_uri: uri.map(|s| s.to_string()),
        }
    }
}

impl From<OAuthError> for OAuthErrorResponse {
    fn from(err: OAuthError) -> Self {
        match err {
            OAuthError::InvalidClient => OAuthErrorResponse::new(
                "invalid_client",
                Some("The client credentials are invalid."),
                None,
            ),
            OAuthError::InvalidScope => OAuthErrorResponse::new(
                "invalid_scope",
                Some("The requested scope is invalid, unknown, or malformed."),
                None,
            ),
            OAuthError::TokenGenerationError => OAuthErrorResponse::new(
                "server_error",
                Some("The authorization server encountered an unexpected condition."),
                None,
            ),
            OAuthError::InvalidRequest => OAuthErrorResponse::new(
                "invalid_request",
                Some("The request is missing a required parameter."),
                None,
            ),
            OAuthError::InvalidGrant => OAuthErrorResponse::new(
                "invalid_grant",
                Some("The provided authorization grant is invalid."),
                None,
            ),
            OAuthError::UnauthorizedClient => OAuthErrorResponse::new(
                "unauthorized_client",
                Some("The client is not authorized to request an access token using this method."),
                None,
            ),
            OAuthError::UnsupportedGrantType => OAuthErrorResponse::new(
                "unsupported_grant_type",
                Some("The authorization grant type is not supported."),
                None,
            ),
            OAuthError::RateLimited => OAuthErrorResponse::new(
                "rate_limited",
                Some("Too many requests have been made in a given amount of time."),
                None,
            ),
            OAuthError::InternalError(desc) => {
                OAuthErrorResponse::new("server_error", Some(&desc), None)
            }
            OAuthError::InvalidCredentials => OAuthErrorResponse::new(
                "invalid_credentials",
                Some("The provided credentials are invalid."),
                None,
            ),
            OAuthError::SessionNotFound => {
                OAuthErrorResponse::new("session_not_found", Some("No active session found."), None)
            }
            OAuthError::InvalidToken => OAuthErrorResponse::new(
                "invalid_token",
                Some("The token provided is invalid."),
                None,
            ),
            // Handle other error variants accordingly
        }
    }
}
