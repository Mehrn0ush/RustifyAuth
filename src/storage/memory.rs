use super::{ClientData, StorageBackend};
use crate::core::authorization::AuthorizationCode;
use crate::error::OAuthError;
use std::collections::{HashMap, HashSet};

// MemoryCodeStore for storing authorization codes in memory
pub struct MemoryCodeStore {
    codes: HashMap<String, AuthorizationCode>, // Keyed by authorization code
    revoked_codes: HashSet<String>,            // Set to track revoked authorization codes
}

impl MemoryCodeStore {
    pub fn new() -> Self {
        MemoryCodeStore {
            codes: HashMap::new(),
            revoked_codes: HashSet::new(), // Initialize the set for revoked codes
        }
    }
}

// Trait defining methods to manage authorization codes
pub trait CodeStore {
    fn store_code(&mut self, code: AuthorizationCode);
    fn retrieve_code(&self, code: &str) -> Option<AuthorizationCode>;
    fn revoke_code(&mut self, code: &str) -> bool;
    fn is_code_revoked(&self, code: &str) -> bool;
}

// Implement CodeStore for MemoryCodeStore
impl CodeStore for MemoryCodeStore {
    // Store the authorization code in memory
    fn store_code(&mut self, code: AuthorizationCode) {
        self.codes.insert(code.code.clone(), code); // Store authorization code
    }

    // Retrieve the authorization code if it exists
    fn retrieve_code(&self, code: &str) -> Option<AuthorizationCode> {
        self.codes.get(code).cloned() // Return a clone of the stored code
    }

    // Revoke the authorization code, returning true if successful
    fn revoke_code(&mut self, code: &str) -> bool {
        if self.codes.remove(code).is_some() {
            self.revoked_codes.insert(code.to_string());
            true
        } else {
            false
        }
    }

    // Check if the code has been revoked
    fn is_code_revoked(&self, code: &str) -> bool {
        self.revoked_codes.contains(code)
    }
}

// MemoryTokenStore for managing token revocation in memory
pub struct MemoryTokenStore {
    revoked_access_tokens: HashSet<String>, // Set of revoked access tokens
    revoked_refresh_tokens: HashSet<String>, // Set of revoked refresh tokens
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        MemoryTokenStore {
            revoked_access_tokens: HashSet::new(),
            revoked_refresh_tokens: HashSet::new(),
        }
    }
}

// Trait defining methods for managing token revocation
pub trait TokenStore {
    fn revoke_access_token(&mut self, token: &str) -> bool;
    fn revoke_refresh_token(&mut self, token: &str) -> bool;
    fn is_token_revoked(&self, token: &str) -> bool;
}

// Implement TokenStore for MemoryTokenStore
impl TokenStore for MemoryTokenStore {
    // Revoke an access token
    fn revoke_access_token(&mut self, token: &str) -> bool {
        let inserted = self.revoked_access_tokens.insert(token.to_string());
        inserted || self.revoked_access_tokens.contains(token) // Return true if it's revoked
    }

    // Revoke a refresh token
    fn revoke_refresh_token(&mut self, token: &str) -> bool {
        let inserted = self.revoked_refresh_tokens.insert(token.to_string());
        inserted || self.revoked_refresh_tokens.contains(token) // Return true if it's revoked
    }

    // Check if either the access or refresh token has been revoked
    fn is_token_revoked(&self, token: &str) -> bool {
        self.revoked_access_tokens.contains(token) || self.revoked_refresh_tokens.contains(token)
    }
}

/// A simple in-memory storage backend for testing purposes.
pub struct MemoryStorage {
    pub clients: HashMap<String, ClientData>, // Map client ID to `ClientData`
}

impl MemoryStorage {
    pub fn new() -> Self {
        MemoryStorage {
            clients: HashMap::new(),
        }
    }

    /// Add a client to the memory storage.
    pub fn add_client(&mut self, client: ClientData) {
        self.clients.insert(client.client_id.clone(), client);
    }
}

impl StorageBackend for MemoryStorage {
    fn get_client_by_id(&self, client_id: &str) -> Result<Option<ClientData>, OAuthError> {
        // Fetch client from the HashMap
        match self.clients.get(client_id) {
            Some(client_data) => Ok(Some(client_data.clone())), // Return a cloned version of `ClientData`
            None => Ok(None),                                   // Client not found
        }
    }
}
