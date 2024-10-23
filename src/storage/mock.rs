use crate::error::OAuthError;
use crate::storage::{ClientData, StorageBackend};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// A mock implementation of `StorageBackend` for testing purposes.
pub struct MockStorageBackend {
    clients: Mutex<HashMap<String, ClientData>>,
    force_token_issue_failure: Mutex<bool>,
}

impl MockStorageBackend {
    /// Creates a new `MockStorageBackend`.
    pub fn new() -> Self {
        MockStorageBackend {
            clients: Mutex::new(HashMap::new()),
            force_token_issue_failure: Mutex::new(false),
        }
    }

    /// Adds a client to the mock storage.
    pub async fn add_client(&self, client: ClientData) {
        let mut clients = self.clients.lock().unwrap();
        clients.insert(client.client_id.clone(), client);
    }

    /// Forces a token issuance failure for testing purposes.
    pub async fn force_token_issuance_failure(&self) {
        let mut failure_flag = self.force_token_issue_failure.lock().unwrap();
        *failure_flag = true;
    }

    /// Simulates token storage (not part of `StorageBackend` trait).
    pub fn save_token(&self, _client_id: &str, _token: &str) -> Result<(), OAuthError> {
        let failure_flag = *self.force_token_issue_failure.lock().unwrap();
        if failure_flag {
            Err(OAuthError::TokenGenerationError)
        } else {
            Ok(())
        }
    }

    // Add any additional methods needed for testing here.
}

#[async_trait]
impl StorageBackend for MockStorageBackend {
    /// Retrieves a client's data by ID.
    fn get_client_by_id(&self, client_id: &str) -> Result<Option<ClientData>, OAuthError> {
        let clients = self.clients.lock().unwrap();
        Ok(clients.get(client_id).cloned())
    }
}
