use crate::core::token::{InMemoryTokenStore, TokenStore};
use crate::core::types::TokenError;
use actix_web::{web, HttpResponse};
use log::error;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shared TokenStore type with thread-safe access
type SharedTokenStore = Arc<Mutex<Box<dyn TokenStore + Send + Sync>>>;

#[derive(Debug, Deserialize, Serialize)]
pub struct RevokeTokenRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeTokenResponse {
    pub message: String,
}

/// Token revocation endpoint
pub async fn revoke_token_endpoint(
    req: web::Json<RevokeTokenRequest>,
    token_store: web::Data<SharedTokenStore>,
) -> HttpResponse {
    let token_type_hint = req.token_type_hint.as_deref();

    let mut token_store = match token_store.lock() {
        Ok(guard) => guard,
        Err(_) => {
            error!("Failed to acquire lock on token store");
            return HttpResponse::InternalServerError().json(RevokeTokenResponse {
                message: "Internal server error".to_string(),
            });
        }
    };

    let exp = match get_current_time() {
        Ok(time) => time + 3600, // 1 hour expiration window
        Err(_) => {
            error!("Failed to get current time");
            return HttpResponse::InternalServerError().json(RevokeTokenResponse {
                message: "Internal server error".to_string(),
            });
        }
    };

    // Attempt to revoke the token, handling both access and refresh tokens
    let revoked = match token_type_hint {
        Some("refresh_token") => {
            token_store.revoke_refresh_token(&req.token).is_ok()
                || token_store.revoke_token(req.token.clone(), exp).is_ok()
        }
        Some("access_token") => {
            token_store.revoke_token(req.token.clone(), exp).is_ok()
                || token_store.revoke_refresh_token(&req.token).is_ok()
        }
        _ => {
            // No valid hint provided, try both
            token_store.revoke_token(req.token.clone(), exp).is_ok()
                || token_store.revoke_refresh_token(&req.token).is_ok()
        }
    };

    HttpResponse::Ok().json(RevokeTokenResponse {
        message: if revoked {
            "Token revoked successfully".to_string()
        } else {
            "Token revoked successfully".to_string() // Return OK even if token was not found
        },
    })
}

/*
Expected Behavior According to OAuth 2.0 Token Revocation Specification (RFC 7009)
Per RFC 7009 Section 2.1:

The token_type_hint is optional and serves as a hint to the authorization server.
If the server cannot find the token using the provided hint, it must extend its search to other types of tokens.
The server should respond with an HTTP 200 status code whether the token was successfully revoked or if the client submitted an invalid token.
*/

/// Get the current time as a UNIX timestamp
fn get_current_time() -> Result<u64, TokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| TokenError::InternalError)
}

/// Implementing `warp::reject::Reject` for `TokenError`
/// If you're not using Warp, you can remove or adjust this part accordingly.
/// Remove or modify this if it's not relevant to your project.
impl warp::reject::Reject for TokenError {}

/// Implementing `warp::reply::Reply` for `TokenError`
/// If you're not using Warp, you can remove or adjust this part accordingly.
/// Remove or modify this if it's not relevant to your project.
impl warp::reply::Reply for TokenError {
    fn into_response(self) -> warp::reply::Response {
        match self {
            TokenError::InvalidToken => warp::reply::with_status(
                "Invalid or expired token",
                actix_web::http::StatusCode::BAD_REQUEST,
            )
            .into_response(),
            TokenError::InvalidRequest => warp::reply::with_status(
                "Invalid token revocation request",
                actix_web::http::StatusCode::BAD_REQUEST,
            )
            .into_response(),
            TokenError::InternalError => warp::reply::with_status(
                "Internal server error",
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            )
            .into_response(),
            _ => warp::reply::with_status(
                "Unhandled error",
                actix_web::http::StatusCode::BAD_REQUEST,
            )
            .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::token::{InMemoryTokenStore, TokenStore};
    use actix_web::{test, web, App};
    use std::sync::{Arc, Mutex};

    type SharedTokenStore = Arc<Mutex<Box<dyn TokenStore + Send + Sync>>>;

    #[actix_web::test]
    async fn test_revoke_token_success() {
        let token_store: SharedTokenStore =
            Arc::new(Mutex::new(Box::new(InMemoryTokenStore::new())));

        // Insert a refresh token to simulate revocation
        let token = "test_token".to_string();
        let exp = get_current_time().unwrap() + 36000; // Extend the expiration time

        // Store the refresh token with correct parameters
        token_store
            .lock()
            .unwrap()
            .store_refresh_token(&token, "client_id", "test_token_id", exp, None)
            .unwrap();

        let req_body = RevokeTokenRequest {
            token: token.clone(),
            token_type_hint: Some("refresh_token".to_string()),
        };

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(token_store.clone()))
                .route("/revoke", web::post().to(revoke_token_endpoint)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/revoke")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let resp_body: RevokeTokenResponse = test::read_body_json(resp).await;

        // Check that the response indicates success
        assert_eq!(resp_body.message, "Token revoked successfully");

        // Validate that the token has been revoked
        let result = token_store
            .lock()
            .unwrap()
            .validate_refresh_token(&token, "client_id");
        assert!(
            result.is_err(),
            "Expected token revocation to fail, but validation succeeded."
        );
    }

    #[actix_web::test]
    async fn test_revoke_token_invalid() {
        let token_store: SharedTokenStore =
            Arc::new(Mutex::new(Box::new(InMemoryTokenStore::new())));

        // Attempt to revoke an invalid token
        let invalid_token = "invalid_token".to_string();

        let req_body = RevokeTokenRequest {
            token: invalid_token.clone(),
            token_type_hint: Some("access_token".to_string()),
        };

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(token_store.clone()))
                .route("/revoke", web::post().to(revoke_token_endpoint)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/revoke")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let resp_body: RevokeTokenResponse = test::read_body_json(resp).await;

        // Check that the response still indicates success, per RFC 7009
        assert_eq!(resp_body.message, "Token revoked successfully");

        // Validate that the token does not exist and revocation has no effect
        let result = token_store
            .lock()
            .unwrap()
            .validate_refresh_token(&invalid_token, "client_id");
        assert!(
            result.is_err(),
            "Expected invalid token revocation to fail, but validation succeeded."
        );
    }

    #[actix_web::test]
    async fn test_revoke_token_with_hint() {
        let token_store: SharedTokenStore =
            Arc::new(Mutex::new(Box::new(InMemoryTokenStore::new())));

        // Insert a refresh token to simulate revocation
        let token = "test_refresh_token".to_string();
        let exp = get_current_time().unwrap() + 36000; // Extend the expiration time

        // Store the refresh token with correct parameters
        token_store
            .lock()
            .unwrap()
            .store_refresh_token(&token, "client_id", "test_token_id", exp, None)
            .unwrap();

        let req_body = RevokeTokenRequest {
            token: token.clone(),
            token_type_hint: Some("refresh_token".to_string()),
        };

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(token_store.clone()))
                .route("/revoke", web::post().to(revoke_token_endpoint)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/revoke")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let resp_body: RevokeTokenResponse = test::read_body_json(resp).await;

        // Check that the response indicates success
        assert_eq!(resp_body.message, "Token revoked successfully");

        // Validate that the token has been revoked
        let result = token_store
            .lock()
            .unwrap()
            .validate_refresh_token(&token, "client_id");
        assert!(
            result.is_err(),
            "Expected token revocation to fail, but validation succeeded."
        );
    }
}
