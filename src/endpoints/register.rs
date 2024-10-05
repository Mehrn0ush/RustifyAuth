use crate::core::token::JwtTokenGenerator;
use crate::core::token::{InMemoryTokenStore, RedisTokenStore, TokenStore};
use crate::security::access_control::RBAC;
use actix_web::HttpRequest;
use actix_web::{web, HttpResponse, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use rsa::pkcs1::LineEnding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

// Structs for handling client metadata and registration responses

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub software_statement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: String,
}

// The Client struct to store registered client data
#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub software_statement: Option<String>,
    pub tbid: Option<String>,
}

// ClientStore with token storage (InMemory or Redis)
pub struct ClientStore<T: TokenStore> {
    pub clients: HashMap<String, Client>,
    pub client_secrets: HashMap<String, String>,
    pub token_store: Arc<T>,
}

impl<T: TokenStore> ClientStore<T> {
    pub fn new(token_store: T) -> Self {
        Self {
            clients: HashMap::new(),
            client_secrets: HashMap::new(),
            token_store: Arc::new(token_store),
        }
    }
}

// Client registration handler

pub async fn register_client_handler<T: TokenStore>(
    store: web::Data<RwLock<ClientStore<T>>>,
    metadata: web::Json<ClientMetadata>,
    credentials: BearerAuth,
    req: HttpRequest,
) -> impl Responder {
    // Perform RBAC check (ensure the user is authorized)
    if let Err(_) = rbac_check(credentials.token(), "admin") {
        return HttpResponse::Unauthorized().json("Unauthorized client");
    }

    // Extract TBID from the request headers
    let tbid = match extract_tbid(&req) {
        Ok(tbid) => Some(tbid),
        Err(_) => None,
    };

    let client_id = generate_client_id();
    let client_secret = generate_client_secret();

    // Create the client and store it in the ClientStore
    let client = Client {
        client_id: client_id.clone(),
        client_name: metadata.client_name.clone(),
        redirect_uris: metadata.redirect_uris.clone(),
        grant_types: metadata.grant_types.clone(),
        response_types: metadata.response_types.clone(),
        software_statement: metadata.software_statement.clone(),
        tbid,
    };

    let mut store = store.write().unwrap();
    store.clients.insert(client_id.clone(), client);
    store
        .client_secrets
        .insert(client_id.clone(), client_secret.clone());

    // Respond with client_id and client_secret
    HttpResponse::Ok().json(ClientRegistrationResponse {
        client_id,
        client_secret,
    })
}

// Helper function to generate client ID
fn generate_client_id() -> String {
    format!("client_{}", Uuid::new_v4())
}

// Helper function to generate client secret
fn generate_client_secret() -> String {
    format!("secret_{}", Uuid::new_v4())
}

// Helper function to extract TBID (Token Binding ID)
pub fn extract_tbid(req: &HttpRequest) -> Result<String, &'static str> {
    if let Some(tbid_header) = req.headers().get("X-Token-Binding") {
        if let Ok(tbid_str) = tbid_header.to_str() {
            Ok(tbid_str.to_string())
        } else {
            Err("Invalid TBID")
        }
    } else {
        Err("Missing TBID")
    }
}

// RBAC check mock function for testing
pub fn rbac_check(token: &str, required_role: &str) -> Result<(), &'static str> {
    // Mock implementation, replace with actual RBAC logic
    if token == "valid_admin_token" && required_role == "admin" {
        Ok(())
    } else {
        Err("Unauthorized")
    }
}

// Tests for client registration

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use std::sync::RwLock;

    #[actix_web::test]
    async fn test_register_client_success() {
        let store = web::Data::new(RwLock::new(ClientStore::new(InMemoryTokenStore::new())));

        let metadata = ClientMetadata {
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/register",
            web::post().to(register_client_handler::<InMemoryTokenStore>),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/register")
            .insert_header(("Authorization", "Bearer valid_admin_token"))
            .set_json(&metadata)
            .to_request();

        let resp: ClientRegistrationResponse = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.client_id.is_empty());
        assert!(!resp.client_secret.is_empty());

        // Verify that the client is stored
        let store = store.read().unwrap();
        assert!(store.clients.contains_key(&resp.client_id));
        assert!(store.client_secrets.contains_key(&resp.client_id));
    }

    #[actix_web::test]
    async fn test_register_client_unauthorized() {
        let store = web::Data::new(RwLock::new(ClientStore::new(InMemoryTokenStore::new())));
        let metadata = ClientMetadata {
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/register",
            web::post().to(register_client_handler::<InMemoryTokenStore>),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/register")
            .insert_header(("Authorization", "Bearer invalid_token"))
            .set_json(&metadata)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn test_register_client_with_tbid() {
        let store = web::Data::new(RwLock::new(ClientStore::new(InMemoryTokenStore::new())));
        let metadata = ClientMetadata {
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/register",
            web::post().to(register_client_handler::<InMemoryTokenStore>),
        ))
        .await;

        let tbid = "tbid_example_value";
        let req = test::TestRequest::post()
            .uri("/register")
            .insert_header(("Authorization", "Bearer valid_admin_token"))
            .insert_header(("X-Token-Binding", tbid))
            .set_json(&metadata)
            .to_request();

        let resp: ClientRegistrationResponse = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.client_id.is_empty());
        assert!(!resp.client_secret.is_empty());

        let store = store.read().unwrap();
        let stored_client = store.clients.get(&resp.client_id).unwrap();

        assert_eq!(stored_client.tbid, Some(tbid.to_string()));
    }
}
