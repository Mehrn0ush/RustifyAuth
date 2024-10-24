use crate::core::token::InMemoryTokenStore;
use crate::core::token::TokenStore;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// Structs for Update requests and responses

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientUpdateRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub software_statement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientUpdateResponse {
    pub message: String,
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
    pub token_store: std::sync::Arc<T>,
}

impl<T: TokenStore> ClientStore<T> {
    pub fn new(token_store: T) -> Self {
        Self {
            clients: HashMap::new(),
            client_secrets: HashMap::new(),
            token_store: std::sync::Arc::new(token_store),
        }
    }
}

// Update Client Handler
pub async fn update_client_handler<T: TokenStore>(
    store: web::Data<RwLock<ClientStore<T>>>,
    client_id: web::Path<String>,
    update: web::Json<ClientUpdateRequest>,
    credentials: BearerAuth,
    req: HttpRequest,
) -> impl Responder {
    // Perform RBAC check (ensure the user is authorized)
    if let Err(_) = rbac_check(credentials.token(), "admin") {
        return HttpResponse::Unauthorized().json("Unauthorized client");
    }

    let client_id = client_id.into_inner();

    let mut store = store.write().unwrap();

    // Check if the client exists
    if let Some(client) = store.clients.get_mut(&client_id) {
        // Update fields if provided
        if let Some(ref name) = update.client_name {
            client.client_name = name.clone();
        }
        if let Some(ref uris) = update.redirect_uris {
            client.redirect_uris = uris.clone();
        }
        if let Some(ref grants) = update.grant_types {
            client.grant_types = grants.clone();
        }
        if let Some(ref responses) = update.response_types {
            client.response_types = responses.clone();
        }
        if let Some(ref sw_statement) = update.software_statement {
            client.software_statement = Some(sw_statement.clone());
        }

        HttpResponse::Ok().json(ClientUpdateResponse {
            message: "Client updated successfully".to_string(),
        })
    } else {
        HttpResponse::NotFound().json("Client not found")
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::token::InMemoryTokenStore;
    use actix_web::{test, web, App};
    use std::sync::RwLock;

    #[actix_web::test]
    async fn test_update_client_not_found() {
        let store = web::Data::new(RwLock::new(ClientStore::new(InMemoryTokenStore::new())));

        let update_metadata = ClientUpdateRequest {
            client_name: Some("Non-Existent Client".to_string()),
            redirect_uris: None,
            grant_types: None,
            response_types: None,
            software_statement: None,
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/update/{client_id}",
            web::put().to(update_client_handler::<InMemoryTokenStore>),
        ))
        .await;

        let update_req = test::TestRequest::put()
            .uri("/update/non_existent_client_id")
            .insert_header(("Authorization", "Bearer valid_admin_token"))
            .set_json(&update_metadata)
            .to_request();

        let resp = test::call_service(&app, update_req).await;

        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn test_update_client_unauthorized() {
        let store = web::Data::new(RwLock::new(ClientStore::new(InMemoryTokenStore::new())));

        let update_metadata = ClientUpdateRequest {
            client_name: Some("Unauthorized Update".to_string()),
            redirect_uris: None,
            grant_types: None,
            response_types: None,
            software_statement: None,
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/update/{client_id}",
            web::put().to(update_client_handler::<InMemoryTokenStore>),
        ))
        .await;

        let update_req = test::TestRequest::put()
            .uri("/update/existing_client_id")
            .insert_header(("Authorization", "Bearer invalid_token"))
            .set_json(&update_metadata)
            .to_request();

        let resp = test::call_service(&app, update_req).await;

        assert_eq!(resp.status(), 401); // Unauthorized
    }

    #[actix_web::test]
    async fn test_update_client_name() {
        let store = web::Data::new(RwLock::new(ClientStore::new(InMemoryTokenStore::new())));

        let client_id = "existing_client_id".to_string();

        let initial_client = Client {
            client_id: client_id.clone(),
            client_name: "Initial Client".to_string(),
            redirect_uris: vec!["https://initial.com".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
            tbid: None,
        };

        store
            .write()
            .unwrap()
            .clients
            .insert(client_id.clone(), initial_client);

        // Update the client_name
        let update_metadata = ClientUpdateRequest {
            client_name: Some("Updated Client".to_string()),
            redirect_uris: None,
            grant_types: None,
            response_types: None,
            software_statement: None,
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/update/{client_id}",
            web::put().to(update_client_handler::<InMemoryTokenStore>),
        ))
        .await;

        let update_req = test::TestRequest::put()
            .uri(&format!("/update/{}", client_id))
            .insert_header(("Authorization", "Bearer valid_admin_token"))
            .set_json(&update_metadata)
            .to_request();

        let resp = test::call_service(&app, update_req).await;
        assert_eq!(resp.status(), 200);

        // Hold the read lock for the duration of the assertions
        let store_read = store.read().unwrap(); // Extend the lifetime of the lock
        let updated_client = store_read.clients.get(&client_id).unwrap();

        // Now you can safely use updated_client for assertions
        assert_eq!(updated_client.client_name, "Updated Client");
    }

    #[actix_web::test]
    async fn test_update_client_with_missing_fields() {
        let store = web::Data::new(RwLock::new(ClientStore::new(InMemoryTokenStore::new())));

        let client_id = "existing_client_id".to_string();

        let mut initial_client = Client {
            client_id: client_id.clone(),
            client_name: "Initial Client".to_string(),
            redirect_uris: vec!["https://initial.com".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
            tbid: None,
        };

        store
            .write()
            .unwrap()
            .clients
            .insert(client_id.clone(), initial_client.clone());

        // Update with only redirect URIs, leave other fields missing
        let update_metadata = ClientUpdateRequest {
            client_name: None,
            redirect_uris: Some(vec!["https://new-uri.com".to_string()]),
            grant_types: None,
            response_types: None,
            software_statement: None,
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/update/{client_id}",
            web::put().to(update_client_handler::<InMemoryTokenStore>),
        ))
        .await;

        let update_req = test::TestRequest::put()
            .uri(&format!("/update/{}", client_id))
            .insert_header(("Authorization", "Bearer valid_admin_token"))
            .set_json(&update_metadata)
            .to_request();

        let resp = test::call_service(&app, update_req).await;
        assert_eq!(resp.status(), 200); // Successful update

        // Hold the read lock for the duration of the assertions
        let store_read = store.read().unwrap(); // Extend the lifetime of the read lock
        let updated_client = store_read.clients.get(&client_id).unwrap(); // Access the client

        assert_eq!(
            updated_client.redirect_uris,
            vec!["https://new-uri.com".to_string()]
        );
        assert_eq!(updated_client.client_name, "Initial Client"); // Should not be changed
    }
}
