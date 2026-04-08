use crate::core::authorization::{AuthorizationCodeFlow, MockTokenGenerator};
use crate::core::device_flow::{start_device_code_cleanup, DeviceCodeStore};
use crate::core::token::InMemoryTokenStore;
use crate::endpoints::register::ClientStore;
use crate::storage::memory::MemoryCodeStore;
use actix_web::{web, App, HttpServer};
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
pub mod oidc;
pub mod routes;
pub mod security;
pub mod storage;

pub use crate::core::token::{InMemoryTokenStore as DefaultTokenStore, RedisTokenStore};

pub fn setup_tls() -> rustls::ClientConfig {
    security::tls::configure_tls()
}

pub fn create_auth_code_flow() -> Arc<Mutex<AuthorizationCodeFlow>> {
    let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
    let token_generator = Arc::new(MockTokenGenerator);

    Arc::new(Mutex::new(AuthorizationCodeFlow {
        code_store,
        token_generator,
        code_lifetime: Duration::from_secs(300),
        allowed_scopes: vec!["read:documents".to_string(), "write:files".to_string()],
    }))
}

pub fn start_cleanup_task(device_code_store: Arc<DeviceCodeStore>) {
    start_device_code_cleanup(device_code_store.into());
}

pub async fn run_mock_server(bind_addr: (&str, u16)) -> std::io::Result<()> {
    let token_store = InMemoryTokenStore::new();
    let client_store = web::Data::new(RwLock::new(ClientStore::new(token_store)));
    let authenticator: Arc<dyn authentication::UserAuthenticator + Send + Sync> =
        Arc::new(auth::mock::MockUserAuthenticator::new());
    let session_manager: Arc<dyn authentication::SessionManager + Send + Sync> =
        Arc::new(auth::mock::MockSessionManager::new());
    let oidc_config = web::Data::new(config::OidcConfig::default());

    HttpServer::new(move || {
        App::new()
            .app_data(client_store.clone())
            .app_data(oidc_config.clone())
            .app_data(web::Data::new(authenticator.clone()))
            .app_data(web::Data::new(session_manager.clone()))
            .configure(routes::init_routes)
    })
    .bind(bind_addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_auth_code_flow_uses_expected_defaults() {
        let flow = create_auth_code_flow();
        let flow = flow.lock().unwrap();

        assert_eq!(flow.code_lifetime, Duration::from_secs(300));
        assert_eq!(
            flow.allowed_scopes,
            vec!["read:documents".to_string(), "write:files".to_string()]
        );
    }
}
