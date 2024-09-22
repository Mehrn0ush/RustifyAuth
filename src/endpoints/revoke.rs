use crate::core::types::TokenError;
use crate::storage::memory;
use crate::storage::memory::TokenStore; // This should handle storing and revoking tokens
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use warp::http::StatusCode;
use warp::{reject, reply, Reply};

// Token revocation request format (based on RFC 7009)
#[derive(Debug, Deserialize)]
pub struct RevokeTokenRequest {
    pub token: String,                   // Token to be revoked (access or refresh)
    pub token_type_hint: Option<String>, // Optional hint: "access_token" or "refresh_token"
}

// Token revocation response
#[derive(Debug, Serialize)]
pub struct RevokeTokenResponse {
    message: String,
}

// The token revocation endpoint
pub async fn revoke_token_endpoint(
    req: RevokeTokenRequest,
    token_store: Arc<Mutex<dyn TokenStore>>, // Shared token store with Mutex for safe concurrency
) -> Result<impl warp::Reply, warp::Rejection> {
    let mut token_store = token_store
        .lock()
        .map_err(|_| warp::reject::custom(TokenError::InternalError))?;

    let token_type_hint = req.token_type_hint.as_deref().unwrap_or("access_token");

    // Revoke the token based on the type hint
    match token_type_hint {
        "access_token" => {
            if token_store.revoke_access_token(&req.token) {
                Ok(warp::reply::json(&RevokeTokenResponse {
                    message: "Access token revoked successfully".into(),
                }))
            } else {
                Err(warp::reject::custom(TokenError::InvalidRequest)) // Use InvalidRequest instead
            }
        }
        "refresh_token" => {
            if token_store.revoke_refresh_token(&req.token) {
                Ok(warp::reply::json(&RevokeTokenResponse {
                    message: "Refresh token revoked successfully".into(),
                }))
            } else {
                Err(warp::reject::custom(TokenError::InvalidRequest)) // Use InvalidRequest instead
            }
        }
        _ => Err(warp::reject::custom(TokenError::InvalidRequest)), // Use InvalidRequest instead
    }
}

// Error handling for token revocation
impl warp::reject::Reject for TokenError {}

impl warp::reply::Reply for TokenError {
    fn into_response(self) -> warp::reply::Response {
        match self {
            TokenError::InvalidToken => {
                warp::reply::with_status("Invalid or expired token", StatusCode::BAD_REQUEST)
                    .into_response()
            }
            TokenError::InvalidTokenTypeHint => {
                warp::reply::with_status("Invalid token_type_hint", StatusCode::BAD_REQUEST)
                    .into_response()
            }
            TokenError::InternalError => {
                warp::reply::with_status("Internal server error", StatusCode::INTERNAL_SERVER_ERROR)
                    .into_response()
            }
            // Add other TokenError variants if you want to handle them explicitly.
            // Or, use the wildcard arm to handle the rest of the cases.
            _ => {
                warp::reply::with_status("Unhandled error", StatusCode::BAD_REQUEST).into_response()
            }
        }
    }
}
