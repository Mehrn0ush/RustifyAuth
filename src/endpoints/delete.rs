

use crate::core::token::TokenStore;
use crate::endpoints::register::Client;
use crate::auth::rbac::rbac_check; // Adjust the path based on your project structure
use actix_web::{web, HttpResponse, Responder, HttpRequest};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use crate::endpoints::update::ClientStore; // Ensure the correct import path

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
///
/// # Returns
///
/// * `HttpResponse` indicating success or failure.
pub async fn delete_client_handler<T: TokenStore>(
    store: web::Data<RwLock<ClientStore<T>>>,
    client_id: web::Path<String>,
    credentials: BearerAuth,
    req: HttpRequest, // If TBID extraction is needed in future
) -> impl Responder {
    // Perform RBAC check to ensure the requester has the 'admin' role.
    if let Err(_) = rbac_check(credentials.token(), "admin") {
        return HttpResponse::Unauthorized().json("Unauthorized client");
    }

    let client_id = client_id.into_inner();

    // Acquire a write lock to modify the client store.
    let mut store = store.write().unwrap();

    // Attempt to remove the client from the store.
    if store.clients.remove(&client_id).is_some() {
        // Also remove the associated client secret.
        store.client_secrets.remove(&client_id);
        HttpResponse::Ok().json(ClientDeleteResponse {
            message: "Client deleted successfully".to_string(),
        })
    } else {
        // If the client does not exist, return a 404 Not Found response.
        HttpResponse::NotFound().json("Client not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use crate::core::token::InMemoryTokenStore;
    use std::sync::RwLock;
    use crate::endpoints::register::{ClientStore, Client};
    use serde_json::json;

    /// Helper function to create a sample client for testing.
    fn create_sample_client(client_id: &str) -> Client {
        Client {
            client_id: client_id.to_string(),
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
            tbid: None,
        }
    }

}
