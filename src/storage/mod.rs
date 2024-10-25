pub mod memory;
pub mod redis;
pub mod sql;
use crate::error::OAuthError;
pub mod backend;
pub mod client;
pub mod mock;
pub mod postgres;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
pub use memory::{CodeStore, TokenStore};

/// `ClientData` stores client information, such as ID, secret, and allowed scopes.
#[derive(Debug, Clone, Default)]
pub struct ClientData {
    pub client_id: String,
    pub secret: String,
    pub allowed_scopes: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct TokenData {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: chrono::NaiveDateTime,
    pub scope: Option<String>,
    pub client_id: String,
}
/// `StorageBackend` defines the trait for interacting with storage backends.

pub trait StorageBackend {
    /// Fetch a client's data using their ID.
    ///
    /// # Arguments
    /// * `client_id` - The ID of the client to fetch.
    ///
    /// # Returns
    /// A `Result<Option<ClientData>, OAuthError>`.
    fn get_client_by_id(&self, client_id: &str) -> Result<Option<ClientData>, OAuthError>;
}

/// Asynchronous StorageBackend for async implementations.
#[async_trait]
pub trait AsyncStorageBackend {
    async fn store_token(&self, token_data: TokenData) -> Result<(), OAuthError>;
    async fn get_token(&self, access_token: &str) -> Result<Option<TokenData>, OAuthError>;
    async fn delete_token(&self, access_token: &str) -> Result<(), OAuthError>;
    async fn get_client_by_id_async(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientData>, OAuthError>;
}
