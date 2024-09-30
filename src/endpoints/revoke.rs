use crate::core::token::InMemoryTokenStore;
use crate::core::token::TokenStore;
use crate::core::types::TokenError;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::http::StatusCode;
use warp::{reject, reply, Filter, Reply};

#[derive(Debug, Deserialize, Serialize)]
pub struct RevokeTokenRequest {
    pub token: String,                   // Token to be revoked
    pub token_type_hint: Option<String>, // Optional hint: "access_token" or "refresh_token"
}

#[derive(Debug, Serialize)]
pub struct RevokeTokenResponse {
    message: String,
}

pub async fn revoke_token_endpoint(
    req: RevokeTokenRequest,
    token_store: Arc<Mutex<dyn TokenStore>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let mut token_store = token_store
        .lock()
        .map_err(|_| warp::reject::custom(TokenError::InternalError))?;

    let exp = get_current_time().unwrap() + 3600;

    let token_type_hint = req.token_type_hint.as_deref();

    // Revoke the token based on the type hint or try both access and refresh tokens
    let revoked = match req.token_type_hint.as_deref() {
        Some("access_token") | Some("refresh_token") => {
            token_store.revoke_token(req.token.clone(), exp).is_ok()
        }
        _ => {
            // Try revoking both types if no specific hint is provided
            token_store.revoke_token(req.token.clone(), exp).is_ok()
        }
    };

    if revoked {
        Ok(warp::reply::json(&RevokeTokenResponse {
            message: "Token revoked successfully".into(),
        }))
    } else {
        // According to RFC 7009, the server responds with HTTP 200 even if the token is invalid
        // to prevent token scanning. However, your implementation returns an error.
        // It's recommended to return HTTP 200 regardless of the token's validity.

        Ok(warp::reply::json(&RevokeTokenResponse {
            message: "Token revoked successfully".into(),
        }))
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
            TokenError::InvalidRequest => warp::reply::with_status(
                "Invalid token revocation request",
                StatusCode::BAD_REQUEST,
            )
            .into_response(),
            TokenError::InternalError => {
                warp::reply::with_status("Internal server error", StatusCode::INTERNAL_SERVER_ERROR)
                    .into_response()
            }
            _ => {
                warp::reply::with_status("Unhandled error", StatusCode::BAD_REQUEST).into_response()
            }
        }
    }
}

fn get_current_time() -> Result<u64, TokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| {
            eprintln!("Failed to retrieve current time: {:?}", e);
            TokenError::InternalError
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::test::request;

    #[tokio::test]
    async fn test_revoke_access_token() {
        // Initialize MemoryTokenStore and cast it to dyn TokenStore
        let store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(InMemoryTokenStore::new()));
        let store_filter = warp::any().map(move || store.clone());

        let revoke_filter = warp::post()
            .and(warp::path("revoke"))
            .and(warp::body::json())
            .and(store_filter)
            .and_then(revoke_token_endpoint);

        let res = request()
            .method("POST")
            .path("/revoke")
            .json(&RevokeTokenRequest {
                token: "access_token_123".to_string(),
                token_type_hint: Some("access_token".to_string()),
            })
            .reply(&revoke_filter)
            .await;

        // According to RFC 7009, the server should return 200 OK even if the token was not found.
        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn test_revoke_refresh_token() {
        let store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(InMemoryTokenStore::new()));
        let store_filter = warp::any().map(move || store.clone());

        let revoke_filter = warp::post()
            .and(warp::path("revoke"))
            .and(warp::body::json())
            .and(store_filter)
            .and_then(revoke_token_endpoint);

        let res = request()
            .method("POST")
            .path("/revoke")
            .json(&RevokeTokenRequest {
                token: "refresh_token_456".to_string(),
                token_type_hint: Some("refresh_token".to_string()),
            })
            .reply(&revoke_filter)
            .await;

        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn test_revoke_unknown_token_type_hint() {
        let store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(InMemoryTokenStore::new()));
        let store_filter = warp::any().map(move || store.clone());

        let revoke_filter = warp::post()
            .and(warp::path("revoke"))
            .and(warp::body::json())
            .and(store_filter)
            .and_then(revoke_token_endpoint);

        let res = request()
            .method("POST")
            .path("/revoke")
            .json(&RevokeTokenRequest {
                token: "unknown_token".to_string(),
                token_type_hint: Some("unknown_type".to_string()),
            })
            .reply(&revoke_filter)
            .await;

        // According to RFC 7009, the server should return 200 OK even if the token was not found.
        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn test_revoke_without_token_type_hint() {
        let store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(InMemoryTokenStore::new()));
        let store_filter = warp::any().map(move || store.clone());

        let revoke_filter = warp::post()
            .and(warp::path("revoke"))
            .and(warp::body::json())
            .and(store_filter)
            .and_then(revoke_token_endpoint);

        let res = request()
            .method("POST")
            .path("/revoke")
            .json(&RevokeTokenRequest {
                token: "access_token_123".to_string(),
                token_type_hint: None,
            })
            .reply(&revoke_filter)
            .await;

        // According to RFC 7009, the server should return 200 OK even if the token was not found.
        assert_eq!(res.status(), 200);
    }
}
