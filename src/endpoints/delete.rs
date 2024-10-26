use crate::auth::rbac::rbac_check;
use crate::core::token::TokenStore;
use crate::core::types::{ActionMetadata, ClientUpdateResponse as CoreClientUpdateResponse};
use crate::endpoints::register::Client as RegisterClient;
use crate::endpoints::update::Client as UpdateClient;
use crate::endpoints::update::ClientStore;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// Response structure for successful client deletion.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientDeleteResponse {
    pub message: String,
}

/// Handler to delete a registered client.
///
/// # Arguments
///
/// * `store` - Shared data store containing clients and their secrets.
/// * `client_id` - Path parameter identifying the client to delete.
/// * `credentials` - Bearer token for authentication.
/// * `jwt_secret` - JWT secret used for decoding tokens.
///
/// # Returns
///
/// * `HttpResponse` indicating success or failure.
pub async fn delete_client_handler<T: TokenStore>(
    store: web::Data<RwLock<ClientStore<T>>>,
    client_id: web::Path<String>,
    credentials: BearerAuth,
    jwt_secret: web::Data<String>,
    req: HttpRequest,
) -> impl Responder {
    let client_id = client_id.into_inner();

    // Acquire a write lock to modify the client store.
    let mut store = store.write().unwrap();

    // First, check if the client exists.
    if store.clients.get(&client_id).is_none() {
        // If the client does not exist, return a 404 Not Found response.
        return HttpResponse::NotFound().json("Client not found");
    }

    // Perform RBAC check to ensure the requester has the 'admin' role.
    if let Err(_) = rbac_check(credentials.token(), "admin", jwt_secret.as_str()) {
        return HttpResponse::Unauthorized().json("Unauthorized client");
    }

    // Proceed to delete the client.
    store.clients.remove(&client_id);
    store.client_secrets.remove(&client_id);

    HttpResponse::Ok().json(ClientDeleteResponse {
        message: "Client deleted successfully".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::token::InMemoryTokenStore;
    use actix_web::{test, web, App};
    use actix_web_httpauth::extractors::bearer::BearerAuth;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    /// Helper function to create a sample client for testing.
    fn create_sample_client(client_id: &str) -> UpdateClient {
        UpdateClient {
            client_id: client_id.to_string(),
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
            tbid: None,
        }
    }

    #[actix_rt::test]
    async fn test_successful_client_deletion() {
        // Create an in-memory token store
        let token_store = std::sync::Arc::new(InMemoryTokenStore::new());

        // Setup the client store with the token_store
        let store = web::Data::new(RwLock::new(ClientStore {
            clients: vec![("client1".to_string(), create_sample_client("client1"))]
                .into_iter()
                .collect(),
            client_secrets: vec![("client1".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
            token_store,
        }));

        let jwt_secret = web::Data::new("test_secret".to_string());

        // Import necessary modules for JWT creation
        use jsonwebtoken::{encode, EncodingKey, Header};
        use serde::{Deserialize, Serialize};

        // Define the JWT claims structure
        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            sub: String,
            exp: usize,
            roles: Vec<String>,
        }

        // Set the expiration time (e.g., current time + 1 hour)
        let expiration = std::time::SystemTime::now()
            .checked_add(std::time::Duration::from_secs(3600))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        // Create the claims with the 'admin' role
        let my_claims = Claims {
            sub: "user1".to_owned(),
            exp: expiration,
            roles: vec!["admin".to_string()],
        };

        // Generate the JWT token
        let token = encode(
            &Header::default(),
            &my_claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap();

        let bearer_token = token;

        let mut app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(jwt_secret.clone())
                .service(
                    web::resource("/clients/{client_id}")
                        .to(delete_client_handler::<InMemoryTokenStore>),
                ),
        )
        .await;

        let req = test::TestRequest::delete()
            .uri("/clients/client1")
            .insert_header(("Authorization", format!("Bearer {}", bearer_token)))
            .to_request();

        let resp = test::call_service(&mut app, req).await;

        // Assert that the status is 200 OK after successful deletion
        assert_eq!(resp.status(), 200);
    }

    #[actix_rt::test]
    async fn test_client_not_found() {
        let store = web::Data::new(RwLock::new(ClientStore {
            clients: HashMap::new(),
            client_secrets: HashMap::new(),
            token_store: Arc::new(InMemoryTokenStore::new()),
        }));

        let jwt_secret = web::Data::new("test_secret".to_string());

        let mut app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(jwt_secret.clone())
                .service(
                    web::resource("/clients/{client_id}")
                        .to(delete_client_handler::<InMemoryTokenStore>),
                ),
        )
        .await;

        let req = test::TestRequest::delete()
            .uri("/clients/non_existing_client")
            .insert_header(("Authorization", "Bearer valid_token_with_admin_role"))
            .to_request();

        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_unauthorized_user() {
        let store = web::Data::new(RwLock::new(ClientStore {
            clients: vec![("client1".to_string(), create_sample_client("client1"))]
                .into_iter()
                .collect::<HashMap<String, UpdateClient>>(),
            client_secrets: vec![("client1".to_string(), "secret".to_string())]
                .into_iter()
                .collect::<HashMap<String, String>>(),
            token_store: Arc::new(InMemoryTokenStore::new()),
        }));

        let jwt_secret = web::Data::new("test_secret".to_string());

        let mut app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(jwt_secret.clone())
                .service(
                    web::resource("/clients/{client_id}")
                        .to(delete_client_handler::<InMemoryTokenStore>),
                ),
        )
        .await;

        let req = test::TestRequest::delete()
            .uri("/clients/client1")
            .insert_header(("Authorization", "Bearer valid_token_without_admin_role"))
            .to_request();

        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 401);
    }
}
