use crate::error::{OAuthError, OAuthErrorResponse };
use crate::core::client_credentials::{issue_token, validate_client_credentials, TokenResponse};
use crate::core::types::TokenRequest;
use crate::storage::{ClientData, StorageBackend};
use actix_web::{web, HttpResponse};
use serde::Deserialize;
use std::sync::Arc;



#[derive(Deserialize)]
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
    log::info!("Handling client credentials for client_id: {}", req.client_id);

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
    match validate_client_credentials(&req.client_id, &req.client_secret, storage.as_ref().as_ref()) {
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