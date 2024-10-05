use crate::core::authorization::AuthorizationCodeFlow;
use crate::core::authorization::MockTokenGenerator;
use crate::storage::memory::MemoryCodeStore;
use security::tls::configure_tls;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use crate::config::OAuthConfig;
use actix_web::{web, App, HttpServer};
use crate::routes::init_routes;
use crate::core::token::{InMemoryTokenStore, RedisTokenStore}; 
use crate::endpoints::register::ClientStore;
use crate::auth::mock::{MockUserAuthenticator, MockSessionManager};


use std::sync::RwLock;


pub mod core;
pub mod authentication;
pub mod endpoints;
pub mod error;
pub mod jwt;
pub mod routes;
pub mod security;
pub mod storage;
pub mod config;
pub mod auth_middleware;
pub mod auth;
pub mod oidc {
    pub mod jwks;  
    pub mod claims;
    pub mod discovery;
}


// Public function to expose TLS setup as part of the library's API
pub fn setup_tls() -> rustls::ClientConfig {
    configure_tls()
}

// Utility function for testing purposes or common calculations
pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn create_auth_code_flow() -> Arc<Mutex<AuthorizationCodeFlow>> {
    let code_store = Arc::new(Mutex::new(MemoryCodeStore::new())); // Initialize code store
    let token_generator = Arc::new(MockTokenGenerator); // Initialize token generator

    let auth_code_flow = AuthorizationCodeFlow {
        code_store,
        token_generator,
        code_lifetime: Duration::from_secs(300), // Example lifetime
        allowed_scopes: vec!["read:documents".to_string(), "write:files".to_string()],
    };

    // Wrap in Arc<Mutex<AuthorizationCodeFlow>> for shared ownership and mutable access
    Arc::new(Mutex::new(auth_code_flow))
}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load configuration
    let config = OAuthConfig::from_env(); // Removed .expect()

    // Initialize token store (In-Memory for simplicity; consider Redis for production)
    let token_store = InMemoryTokenStore::new();
    let client_store = web::Data::new(RwLock::new(ClientStore::new(token_store)));

    // Initialize Authenticator and Session Manager with mock implementations using `new` methods
    let authenticator = Arc::new(auth::mock::MockUserAuthenticator::new());
    let session_manager = Arc::new(auth::mock::MockSessionManager::new());

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(client_store.clone())
            .app_data(web::Data::new(authenticator.clone()))
            .app_data(web::Data::new(session_manager.clone()))
            .configure(init_routes::<auth::mock::MockUserAuthenticator, auth::mock::MockSessionManager>) // Initialize all routes
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}