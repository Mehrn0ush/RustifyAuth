use crate::core::token::InMemoryTokenStore;
use crate::core::token::TokenStore;
use crate::core::types::TokenError;
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::http::StatusCode;
use warp::{reject, reply, Filter, Reply};

#[derive(Debug, Deserialize, Serialize)]
pub struct RevokeTokenRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RevokeTokenResponse {
    message: String,
}

pub async fn revoke_token_endpoint(
    req: web::Json<RevokeTokenRequest>,
    token_store: web::Data<Arc<Mutex<dyn TokenStore>>>,
) -> HttpResponse {
    let mut token_store = token_store.lock().unwrap();

    let token_type_hint = req.token_type_hint.as_deref();
    let exp = get_current_time().unwrap() + 3600;

    // Revoke the token based on the type hint
    let revoked = match token_type_hint {
        Some("access_token") | Some("refresh_token") => {
            token_store.revoke_token(req.token.clone(), exp).is_ok()
        }
        _ => token_store.revoke_token(req.token.clone(), exp).is_ok(),
    };

    // Return success response regardless of token validity, as per RFC 7009
    HttpResponse::Ok().json(RevokeTokenResponse {
        message: "Token revoked successfully".to_string(),
    })
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
