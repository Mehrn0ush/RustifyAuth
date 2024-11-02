use crate::config::OAuthConfig;
use crate::core::authorization::AuthorizationCodeFlow;
use crate::core::authorization::MockTokenGenerator;
use crate::core::device_flow::{start_device_code_cleanup, DeviceCodeStore};
use crate::core::token::{InMemoryTokenStore, RedisTokenStore};
use crate::endpoints::register::ClientStore;
use crate::routes::init_routes;
use crate::storage::memory::MemoryCodeStore;
use crate::storage::postgres::PostgresBackend;
use crate::storage::StorageBackend;
use actix_web::{web, App, HttpServer};
use deadpool_postgres::{Manager, Pool};
use security::tls::configure_tls;
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use std::sync::RwLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub mod auth;
pub mod auth_middleware;
pub mod authentication;
pub mod config;
pub mod core;
pub mod endpoints;
pub mod error;
pub mod jwt;
pub mod routes;
pub mod security;
pub mod storage;
pub mod oidc {
    pub mod claims;
    pub mod discovery;
    pub mod jwks;
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

// Function to start device code cleanup, exported for library users
pub fn start_cleanup_task(device_code_store: Arc<DeviceCodeStore>) {
    start_device_code_cleanup(device_code_store.into());
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
            .configure(
                init_routes::<auth::mock::MockUserAuthenticator, auth::mock::MockSessionManager>,
            ) // Initialize all routes
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[tokio::main]
async fn main1() -> Result<(), sqlx::Error> {
    // Ensure the database is set up
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    if !sqlx::Postgres::database_exists(&database_url).await? {
        sqlx::Postgres::create_database(&database_url).await?;
        println!("Database created");
    }

    // Connect to the database and run migrations
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    sqlx::migrate!().run(&pool).await?; // This runs the migrations

    println!("Migrations applied");

    // Your app initialization code here

    Ok(())
}

/*
// lib.rs
use crate::config::OidcConfig;

pub struct RustifyAuth {
    pub config: OidcConfig,
    // Other fields like services, storage, etc.
}

impl RustifyAuth {
    pub fn new(config: OidcConfig) -> Self {
        RustifyAuth {
            config,
            // Initialize other dependencies
        }
    }

    // Other methods
}

*/
