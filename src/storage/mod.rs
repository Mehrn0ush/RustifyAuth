pub mod memory;
pub mod redis;
pub mod sql;
use crate::error::OAuthError;
pub mod backend;
pub mod client;
pub mod mock;

pub use memory::{CodeStore, TokenStore};

/// `ClientData` stores client information, such as ID, secret, and allowed scopes.
#[derive(Debug, Clone, Default)]
pub struct ClientData {
    pub client_id: String,
    pub secret: String,
    pub allowed_scopes: Vec<String>,
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
