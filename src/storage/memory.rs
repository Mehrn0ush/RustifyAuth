use super::{client, ClientData, StorageBackend};
use crate::core::authorization::AuthorizationCode;
use crate::core::token::Token;
use crate::core::types::TokenError;
use crate::error::OAuthError;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// MemoryCodeStore for storing authorization codes in memory
pub struct MemoryCodeStore {
    codes: HashMap<String, AuthorizationCode>,
    revoked_codes: HashSet<String>,
}

impl MemoryCodeStore {
    pub fn new() -> Self {
        MemoryCodeStore {
            codes: HashMap::new(),
            revoked_codes: HashSet::new(),
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
    revoked_access_tokens: HashSet<String>,
    revoked_refresh_tokens: HashSet<String>,
    active_tokens: Mutex<HashMap<String, Token>>,
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        MemoryTokenStore {
            revoked_access_tokens: HashSet::new(),
            revoked_refresh_tokens: HashSet::new(),
            active_tokens: Mutex::new(HashMap::new()),
        }
    }
}

// Trait defining methods for managing token revocation
pub trait TokenStore {
    fn revoke_access_token(&mut self, token: &str) -> bool;
    fn revoke_refresh_token(&mut self, token: &str) -> bool;
    fn is_token_revoked(&self, token: &str) -> bool;
    fn is_refresh_token_revoked(&self, token: &str) -> bool;
    fn store_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError>;

    fn rotate_refresh_token(
        &mut self,
        old_token: &str,
        new_token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError>;

    fn validate_refresh_token(
        &mut self,
        token: &str,
        client_id: &str,
    ) -> Result<(String, u64), TokenError>;
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

    fn store_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError> {
        let mut active_tokens = self.active_tokens.lock().unwrap();
        active_tokens.insert(
            token.to_string(),
            Token {
                value: token.to_string(),
                expiration: exp,
            },
        );
        Ok(())
    }

    fn rotate_refresh_token(
        &mut self,
        old_token: &str,
        new_token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError> {
        self.revoke_refresh_token(old_token); // Revoke old refresh token
        self.store_refresh_token(new_token, client_id, user_id, exp) // Store new refresh token
    }

    fn validate_refresh_token(
        &mut self,
        token: &str,
        client_id: &str,
    ) -> Result<(String, u64), TokenError> {
        let token_data = {
            let active_tokens = self.active_tokens.lock().unwrap();
            active_tokens.get(token).cloned()
        };
        if let Some(token_data) = token_data {
            if token_data.expiration > get_current_time()? {
                let new_token = generate_new_token();

                // Extract the user_id associated with the token
                let user_id = "user_id_123"; // Here, you would normally extract the actual user_id
                self.rotate_refresh_token(
                    token,
                    &new_token,
                    client_id,
                    user_id,
                    token_data.expiration,
                )?;

                Ok((user_id.to_string(), token_data.expiration))
            } else {
                Err(TokenError::ExpiredToken)
            }
        } else {
            Err(TokenError::InvalidToken)
        }
    }

    fn is_refresh_token_revoked(&self, token: &str) -> bool {
        self.revoked_refresh_tokens.contains(token)
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
// helper function to get the current time
fn get_current_time() -> Result<u64, TokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| {
            eprintln!("Failed to retrieve current time: {:?}", e);
            TokenError::InternalError
        })
}

// Helper function to generate a new refresh token (correct return type)
fn generate_new_token() -> String {
    // Generate a new random token
    "new_refresh_token_placeholder".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::token::Token;

    #[test]
    fn test_store_and_validate_refresh_token() {
        let mut token_store = MemoryTokenStore::new(); // Make token_store mutable
        let refresh_token = "refresh_token_123";
        let client_id = "client_id_123";
        let user_id = "user_id_123";
        let exp = get_current_time().unwrap() + 3600; // Expires in 1 hour

        // Store the refresh token
        assert!(token_store
            .store_refresh_token(refresh_token, client_id, user_id, exp)
            .is_ok());

        // Validate the refresh token
        let validation = token_store.validate_refresh_token(refresh_token, client_id);
        assert!(validation.is_ok());
        let (retrieved_user_id, retrieved_exp) = validation.unwrap();
        assert_eq!(retrieved_user_id, user_id);
        assert_eq!(retrieved_exp, exp);
    }

    #[test]
    fn test_revoke_refresh_token() {
        let mut token_store = MemoryTokenStore::new(); // Make token_store mutable
        let refresh_token = "refresh_token_456";

        // Revoke the refresh token
        assert!(token_store.revoke_refresh_token(refresh_token));

        // Check if the token is revoked
        assert!(token_store.is_refresh_token_revoked(refresh_token));
        assert!(token_store.is_token_revoked(refresh_token));
    }

    #[test]
    fn test_revoke_access_token() {
        let mut token_store = MemoryTokenStore::new(); // Make token_store mutable
        let access_token = "access_token_789";

        // Revoke the access token
        assert!(token_store.revoke_access_token(access_token));

        // Check if the token is revoked
        assert!(token_store.is_token_revoked(access_token));
    }
}
