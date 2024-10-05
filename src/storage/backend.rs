
use async_trait::async_trait;

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn get_client(&self, client_id: &str) -> Option<ClientData>;
    //  other necessary methods (e.g., store_client, revoke_token, etc.)
}

// Example ClientData struct
#[derive(Debug, Clone)]
pub struct ClientData {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    // Add other necessary fields
}
