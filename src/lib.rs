use crate::core::authorization::AuthorizationCodeFlow;
use crate::core::authorization::MockTokenGenerator; // Correct module for MockTokenGenerator
use crate::storage::memory::MemoryCodeStore;
use security::tls::configure_tls;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Expose the core, security, endpoints, and storage modules
pub mod auth_middleware;
pub mod authentication;
pub mod core;
pub mod endpoints;
pub mod error;
pub mod jwt;
pub mod routes;
pub mod security;
pub mod storage;

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
