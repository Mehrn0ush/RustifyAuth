use crate::core::client_credentials::{issue_token, validate_client_credentials, TokenResponse};
use crate::core::types::TokenRequest;
use crate::error::{OAuthError, OAuthErrorResponse};
use crate::storage::mock::MockStorageBackend;
use crate::storage::{ClientData, StorageBackend};
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize, Serialize)]
pub struct ClientCredentialsRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
}

/// Handles the client credentials grant type for OAuth2.
///
/// Validates client credentials and issues an access token if valid.
///
/// # Arguments
///
/// * `req` - The incoming JSON request containing client credentials.
/// * `storage` - The storage backend implementing `StorageBackend`.
///
/// # Returns
///
/// * `HttpResponse` - JSON response with the access token or an error message.
pub async fn handle_client_credentials(
    req: web::Json<ClientCredentialsRequest>,
    storage: web::Data<Arc<dyn StorageBackend>>, // Inject storage backend
) -> HttpResponse {
    // Log the incoming request (avoid logging sensitive information in production)
    log::info!(
        "Handling client credentials for client_id: {}",
        req.client_id
    );

    // Validate the request parameters
    if req.grant_type != "client_credentials" {
        log::warn!("Invalid grant_type received: {}", req.grant_type);
        let error_response = OAuthErrorResponse::new(
            "unsupported_grant_type",
            Some("The grant_type must be 'client_credentials'."),
            None,
        );
        return HttpResponse::BadRequest().json(error_response);
    }

    // Convert `req.scope` from `Option<String>` to `Vec<String>`
    let scopes: Vec<String> = req
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.trim().to_string())
        .collect();

    // Call core functions to validate client and issue token
    match validate_client_credentials(
        &req.client_id,
        &req.client_secret,
        storage.as_ref().as_ref(),
    ) {
        Ok(client) => match issue_token(&client, &scopes) {
            Ok(token_response) => {
                log::info!("Issued token for client_id: {}", req.client_id);
                HttpResponse::Ok().json(token_response)
            }
            Err(err) => {
                log::error!("Failed to issue token: {:?}", err);
                let error_response: OAuthErrorResponse = err.into();
                HttpResponse::InternalServerError().json(error_response)
            }
        },
        Err(err) => {
            log::warn!("Client credentials validation failed: {:?}", err);
            let error_response: OAuthErrorResponse = err.into();
            HttpResponse::Unauthorized().json(error_response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::TokenResponse;
    use crate::error::OAuthErrorResponse;
    use crate::storage::mock::MockStorageBackend;
    use actix_web::{http::StatusCode, test, web, App};
    use std::sync::Arc;

    #[actix_rt::test]
    async fn test_invalid_grant_type() {
        let storage = Arc::new(MockStorageBackend::new());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(storage.clone() as Arc<dyn StorageBackend>))
                .route("/token", web::post().to(handle_client_credentials)),
        )
        .await;

        let req_body = ClientCredentialsRequest {
            grant_type: "invalid_grant".to_string(),
            client_id: "test_client".to_string(),
            client_secret: "test_secret".to_string(),
            scope: None,
        };

        let req = test::TestRequest::post()
            .uri("/token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_invalid_client_credentials() {
        let storage = Arc::new(MockStorageBackend::new());

        // Simulate invalid client credentials
        storage
            .add_client(ClientData {
                client_id: "test_client".to_string(),
                secret: "correct_secret".to_string(), // Correct secret
                allowed_scopes: vec![],
            })
            .await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(storage.clone() as Arc<dyn StorageBackend>))
                .route("/token", web::post().to(handle_client_credentials)),
        )
        .await;

        let req_body = ClientCredentialsRequest {
            grant_type: "client_credentials".to_string(),
            client_id: "test_client".to_string(),
            client_secret: "wrong_secret".to_string(), // Pass wrong secret
            scope: None,
        };

        let req = test::TestRequest::post()
            .uri("/token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED); // Expect 401
    }

    #[actix_rt::test]
    async fn test_successful_token_issuance() {
        let storage = Arc::new(MockStorageBackend::new());

        // Simulate valid client
        storage
            .add_client(ClientData {
                client_id: "test_client".to_string(),
                secret: "test_secret".to_string(),
                allowed_scopes: vec!["test_scope".to_string()],
            })
            .await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(storage.clone() as Arc<dyn StorageBackend>))
                .route("/token", web::post().to(handle_client_credentials)),
        )
        .await;

        let req_body = ClientCredentialsRequest {
            grant_type: "client_credentials".to_string(),
            client_id: "test_client".to_string(),
            client_secret: "test_secret".to_string(),
            scope: Some("test_scope".to_string()),
        };

        let req = test::TestRequest::post()
            .uri("/token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK); // Expect 200

        // Read and print the response body
        let resp_body = test::read_body(resp).await;
        println!("Response body: {}", String::from_utf8_lossy(&resp_body));

        // Ensure the response contains the token
        let token_response: TokenResponse = serde_json::from_slice(&resp_body).unwrap();

        // Assert token fields
        assert!(token_response.access_token.starts_with("eyJ")); // JWT tokens typically start with "eyJ"
        assert_eq!(token_response.refresh_token, ""); // Now refresh_token should be an empty string
    }

    #[actix_rt::test]
    async fn test_token_issuance_error() {
        let storage = Arc::new(MockStorageBackend::new());

        // Simulate valid client, but token issuance fails
        storage
            .add_client(ClientData {
                client_id: "test_client".to_string(),
                secret: "test_secret".to_string(),
                allowed_scopes: vec![],
            })
            .await;
        storage.force_token_issuance_failure().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(storage.clone() as Arc<dyn StorageBackend>))
                .route("/token", web::post().to(handle_client_credentials)),
        )
        .await;

        let req_body = ClientCredentialsRequest {
            grant_type: "client_credentials".to_string(),
            client_id: "test_client".to_string(),
            client_secret: "test_secret".to_string(),
            scope: Some("test_scope".to_string()),
        };

        let req = test::TestRequest::post()
            .uri("/token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
