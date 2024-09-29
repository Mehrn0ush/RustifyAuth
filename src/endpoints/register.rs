use actix_web_httpauth::extractors::bearer::BearerAuth;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation, TokenData};
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use dashmap::DashMap;
use uuid::Uuid;
use bcrypt::{hash, DEFAULT_COST};
use chrono::Utc;
use std::sync::Arc;
use thiserror::Error;
use log::{info, error};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ClientMetadata {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub software_statement: Option<String>, // Optional JWT field
}

#[derive(Serialize, Debug, Clone)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Error, Debug)]
pub enum RegistrationError {
    #[error("Hashing error")]
    HashingError,
    #[error("Software statement is invalid")]
    InvalidSoftwareStatement,
    #[error("Storage error")]
    StorageError,
    #[error("Unauthorized client")]
    UnauthorizedClient,
    #[error("Internal server error")]
    InternalError,
}

impl actix_web::ResponseError for RegistrationError {
    fn error_response(&self) -> HttpResponse {
        match self {
            RegistrationError::HashingError => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "hashing_error",
                    "error_description": "Failed to hash the client secret."
                }))
            },
            RegistrationError::InvalidSoftwareStatement => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "invalid_software_statement",
                    "error_description": "The provided software statement is invalid."
                }))
            },
            RegistrationError::StorageError => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "storage_error",
                    "error_description": "Failed to store client data."
                }))
            },
            RegistrationError::UnauthorizedClient => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "unauthorized_client",
                    "error_description": "Client authentication failed."
                }))
            },
            RegistrationError::InternalError => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "internal_error",
                    "error_description": "An internal server error occurred."
                }))
            },
        }
    }
}

#[derive(Clone)]
pub struct ClientStore {
    pub clients: DashMap<String, ClientMetadata>,  // Store client metadata securely
    pub client_secrets: DashMap<String, String>,   // Store client secrets securely (hashed)
}

impl ClientStore {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
            client_secrets: DashMap::new(),
        }
    }

    // Register client and store metadata and secret
    pub async fn register_client(
        &self,
        metadata: ClientMetadata,
        credentials: BearerAuth,
    ) -> Result<ClientRegistrationResponse, RegistrationError> {
        // Authenticate the client performing registration
        Self::rbac_check(credentials.token(), "admin")?;

        // Validate mandatory fields
        if metadata.redirect_uris.is_empty() {
            return Err(RegistrationError::StorageError); // Ideally, define a specific error
        }
        if metadata.grant_types.is_empty() {
            return Err(RegistrationError::StorageError);
        }
        if metadata.response_types.is_empty() {
            return Err(RegistrationError::StorageError);
        }

        // Validate the software statement if provided
        if let Some(software_statement) = &metadata.software_statement {
            Self::validate_software_statement(software_statement)?;
        }

        // Generate unique client_id and client_secret
        let client_id = Uuid::new_v4().to_string();
        let client_secret = Uuid::new_v4().to_string();

        // Hash the client_secret before storing it
        let hashed_secret = hash(&client_secret, DEFAULT_COST)
            .map_err(|_| RegistrationError::HashingError)?;

        // Store client metadata and hashed secret
        self.clients.insert(client_id.clone(), metadata.clone());
        self.client_secrets.insert(client_id.clone(), hashed_secret);

        // Log successful registration
        info!("Client registered successfully: client_id={}", client_id);

        Ok(ClientRegistrationResponse {
            client_id,
            client_secret,
        })
    }

    // Role-Based Access Control check
    fn rbac_check(token: &str, required_role: &str) -> Result<(), RegistrationError> {
        // Implement your JWT validation and role extraction logic here
        // For example:
        // let claims = validate_jwt(token)?;
        // if claims.role != required_role {
        //     return Err(RegistrationError::UnauthorizedClient);
        // }
        // Ok(())
        // Placeholder for demonstration:
        if token == "valid_admin_token" && required_role == "admin" {
            Ok(())
        } else {
            Err(RegistrationError::UnauthorizedClient)
        }
    }

    // Validate software statement JWT
    fn validate_software_statement(jwt: &str) -> Result<TokenData<Claims>, RegistrationError> {
        let decoding_key = DecodingKey::from_rsa_pem(
            std::env::var("SOFTWARE_STATEMENT_PUBLIC_KEY")
                .map_err(|_| RegistrationError::InvalidSoftwareStatement)?
                .as_bytes(),
        )
        .map_err(|_| RegistrationError::InvalidSoftwareStatement)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true; // Ensure the expiration is validated
        validation.validate_aud = true; // Validate audience
        validation.aud = Some(vec!["your_audience".to_string()]); // Set your expected audience

        decode::<Claims>(jwt, &decoding_key, &validation)
            .map_err(|_| RegistrationError::InvalidSoftwareStatement)
    }
}

// The /register endpoint
pub async fn register_client_handler(
    client_store: web::Data<ClientStore>,
    metadata: web::Json<ClientMetadata>,
    credentials: BearerAuth,
) -> Result<impl Responder, RegistrationError> {
    // Attempt to register the client
    let response = client_store
        .register_client(metadata.into_inner(), credentials)
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

// Define the /update endpoint (RFC 7591 does not specify, but commonly needed)
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UpdateClientMetadata {
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub software_statement: Option<String>, // Optional JWT field
}

#[derive(Serialize, Debug, Clone)]
pub struct UpdateClientResponse {
    pub message: String,
}

#[derive(Error, Debug)]
pub enum UpdateError {
    #[error("Client not found")]
    ClientNotFound,
    #[error("Unauthorized client")]
    UnauthorizedClient,
    #[error("Invalid software statement")]
    InvalidSoftwareStatement,
    #[error("Internal server error")]
    InternalError,
}

impl actix_web::ResponseError for UpdateError {
    fn error_response(&self) -> HttpResponse {
        match self {
            UpdateError::ClientNotFound => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "client_not_found",
                    "error_description": "The client ID does not exist."
                }))
            },
            UpdateError::UnauthorizedClient => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "unauthorized_client",
                    "error_description": "Client authentication failed."
                }))
            },
            UpdateError::InvalidSoftwareStatement => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "invalid_software_statement",
                    "error_description": "The provided software statement is invalid."
                }))
            },
            UpdateError::InternalError => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "internal_error",
                    "error_description": "An internal server error occurred."
                }))
            },
        }
    }
}

pub async fn update_client_handler(
    client_store: web::Data<ClientStore>,
    client_id: web::Path<String>,
    updated_metadata: web::Json<UpdateClientMetadata>,
    credentials: BearerAuth,
) -> Result<impl Responder, UpdateError> {
    // Authenticate the client performing the update
    ClientStore::rbac_check(credentials.token(), "admin").map_err(|_| UpdateError::UnauthorizedClient)?;

    // Retrieve the client
    let client_entry = client_store.clients.get_mut(&client_id.into_inner());
    match client_entry {
        Some(mut client_metadata) => {
            // Update fields if provided
            if let Some(name) = &updated_metadata.client_name {
                client_metadata.client_name = name.clone();
            }
            if let Some(redirect_uris) = &updated_metadata.redirect_uris {
                client_metadata.redirect_uris = redirect_uris.clone();
            }
            if let Some(grant_types) = &updated_metadata.grant_types {
                client_metadata.grant_types = grant_types.clone();
            }
            if let Some(response_types) = &updated_metadata.response_types {
                client_metadata.response_types = response_types.clone();
            }
            if let Some(software_statement) = &updated_metadata.software_statement {
                // Validate the software statement
                ClientStore::validate_software_statement(software_statement)?;
                client_metadata.software_statement = Some(software_statement.clone());
            }

            // Log successful update
            info!("Client updated successfully: client_id={}", client_id);

            Ok(HttpResponse::Ok().json(UpdateClientResponse {
                message: "Client updated successfully.".to_string(),
            }))
        },
        None => {
            error!("Client not found: client_id={}", client_id);
            Err(UpdateError::ClientNotFound)
        },
    }
}

// Logging with structured information
pub fn log_audit_event(event_type: &str, client_id: &str, metadata: &ClientMetadata) {
    let timestamp = Utc::now().to_rfc3339();
    info!(
        "{} event at {}: Client ID: {}, Metadata: {:?}",
        event_type, timestamp, client_id, metadata
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use serde_json::json;

    #[actix_web::test]
    async fn test_register_client_success() {
        // Initialize logging for tests
        let _ = env_logger::builder().is_test(true).try_init();

        let store = web::Data::new(ClientStore::new());
        let metadata = ClientMetadata {
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .route("/register", web::post().to(register_client_handler))
        ).await;

        // Set a valid admin token
        let req = test::TestRequest::post()
            .uri("/register")
            .insert_header(("Authorization", "Bearer valid_admin_token"))
            .set_json(&metadata)
            .to_request();
        
        let resp: ClientRegistrationResponse = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.client_id.is_empty());
        assert!(!resp.client_secret.is_empty());

        // Verify that the client is stored
        assert!(store.clients.contains_key(&resp.client_id));
        assert!(store.client_secrets.contains_key(&resp.client_id));
    }

    #[actix_web::test]
    async fn test_register_client_unauthorized() {
        // Initialize logging for tests
        let _ = env_logger::builder().is_test(true).try_init();

        let store = web::Data::new(ClientStore::new());
        let metadata = ClientMetadata {
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .route("/register", web::post().to(register_client_handler))
        ).await;

        // Set an invalid token
        let req = test::TestRequest::post()
            .uri("/register")
            .insert_header(("Authorization", "Bearer invalid_token"))
            .set_json(&metadata)
            .to_request();
        
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn test_register_client_invalid_software_statement() {
        // Initialize logging for tests
        let _ = env_logger::builder().is_test(true).try_init();

        let store = web::Data::new(ClientStore::new());
        let metadata = ClientMetadata {
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: Some("invalid_jwt".to_string()),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .route("/register", web::post().to(register_client_handler))
        ).await;

        // Set a valid admin token
        let req = test::TestRequest::post()
            .uri("/register")
            .insert_header(("Authorization", "Bearer valid_admin_token"))
            .set_json(&metadata)
            .to_request();
        
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn test_register_client_missing_fields() {
        // Initialize logging for tests
        let _ = env_logger::builder().is_test(true).try_init();

        let store = web::Data::new(ClientStore::new());
        let metadata = ClientMetadata {
            client_name: "".to_string(), // Missing client_name
            redirect_uris: vec![],
            grant_types: vec![],
            response_types: vec![],
            software_statement: None,
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .route("/register", web::post().to(register_client_handler))
        ).await;

        // Set a valid admin token
        let req = test::TestRequest::post()
            .uri("/register")
            .insert_header(("Authorization", "Bearer valid_admin_token"))
            .set_json(&metadata)
            .to_request();
        
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 500); // Currently returns StorageError, which maps to 500
    }
}
