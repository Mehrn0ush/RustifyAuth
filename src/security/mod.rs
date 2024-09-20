pub mod encryption;
pub mod mfa;
pub mod rate_limit;  
use crate::error::OAuthError;

/// `ClientData` will store client-related information (e.g., ID, secret, allowed scopes).
#[derive(Debug, Clone)]
pub struct ClientData {
    pub client_id: String,
    pub secret: String,
    pub allowed_scopes: Vec<String>,
}

/// The `StorageBackend` trait defines the interface that any storage backend must implement.
pub trait StorageBackend {
    /// Fetch a client's data using their ID.
    ///
    /// # Arguments
    /// * `client_id` - The ID of the client to fetch.
    ///
    /// # Returns
    /// A `Result<Option<ClientData>, OAuthError>`. Returns `Ok(Some(ClientData))` if found, `Ok(None)` if not found, or an error.
    fn get_client_by_id(&self, client_id: &str) -> Result<Option<ClientData>, OAuthError>;
}
