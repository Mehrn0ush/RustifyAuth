use super::{ClientData, StorageBackend};
use crate::core::authorization::AuthorizationCode;
use crate::core::types::TokenError;
use crate::error::OAuthError;
use crate::storage::{CodeStore, TokenStore};
use redis::Client;
use redis::{Commands, Connection, RedisError};
use serde::{Deserialize, Serialize};
use serde_json;
use std::cell::RefCell;

pub struct RedisCodeStore {
    conn: RefCell<Connection>, // Use RefCell for interior mutability
}

impl RedisCodeStore {
    pub fn new(conn: Connection) -> Self {
        RedisCodeStore {
            conn: RefCell::new(conn), // Wrap the connection in RefCell for mutability
        }
    }

    // Retrieve an AuthorizationCode from Redis
    fn retrieve_code_from_redis(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, RedisError> {
        let mut conn = self.conn.borrow_mut(); // Mutably borrow the Redis connection for the `get` operation
        let result: Result<String, RedisError> = conn.get(code); // Fetch the code from Redis

        match result {
            Ok(data) => {
                // Deserialize the JSON string back into an AuthorizationCode object
                serde_json::from_str(&data).map(Some).map_err(|err| {
                    eprintln!("Failed to deserialize AuthorizationCode: {}", err);
                    RedisError::from((redis::ErrorKind::TypeError, "Deserialization Error"))
                })
            }
            Err(err) => {
                eprintln!("Error fetching code from Redis: {}", err);
                Err(err) // Propagate the Redis error
            }
        }
    }
}

impl CodeStore for RedisCodeStore {
    // Store the authorization code in Redis
    fn store_code(&mut self, code: AuthorizationCode) {
        let mut conn = self.conn.borrow_mut(); // Mutably borrow the Redis connection for the `set` operation
        let result: Result<(), RedisError> = conn.set(
            code.code.clone(),
            serde_json::to_string(&code).unwrap_or_else(|_| String::new()), // Serialize AuthorizationCode
        );

        if let Err(err) = result {
            eprintln!("Error storing code in Redis: {}", err);
        }
    }

    // Retrieve an authorization code from Redis
    fn retrieve_code(&self, code: &str) -> Option<AuthorizationCode> {
        self.retrieve_code_from_redis(code).ok().flatten() // Use the safe version and handle errors gracefully
    }

    // Revoke (delete) the authorization code from Redis
    fn revoke_code(&mut self, code: &str) -> bool {
        let mut conn = self.conn.borrow_mut(); // Mutably borrow the Redis connection for the `del` operation
        let result: Result<(), RedisError> = conn.del(code); // Delete the code from Redis

        if let Err(err) = result {
            eprintln!("Error revoking code in Redis: {}", err);
            false
        } else {
            true
        }
    }

    // Check if the code is revoked in Redis
    fn is_code_revoked(&self, code: &str) -> bool {
        let mut conn = self.conn.borrow_mut();
        let result: Result<bool, RedisError> = conn.exists(code);
        // result.unwrap_or(false)  // Return false if the check fails
        match result {
            Ok(exists) => !exists, // If code exists, it is not revoked, so return false
            Err(err) => {
                eprintln!("Error checking if code is revoked: {}", err);
                false
            }
        }
    }
}

pub struct RedisTokenStore {
    conn: RefCell<Connection>, // Use RefCell for interior mutability
}

impl RedisTokenStore {
    pub fn new(conn: Connection) -> Self {
        RedisTokenStore {
            conn: RefCell::new(conn), // Initialize connection inside RefCell for mutability
        }
    }
}

impl TokenStore for RedisTokenStore {
    // Revoke access token by adding it to the revoked set
    fn revoke_access_token(&mut self, token: &str) -> bool {
        let mut conn = self.conn.borrow_mut(); // Mutably borrow the Redis connection for the `sadd` operation
        let result: Result<(), RedisError> = conn.sadd("revoked_access_tokens", token);

        if let Err(err) = result {
            eprintln!("Error revoking access token: {}", err);
            false
        } else {
            true
        }
    }

    fn store_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError> {
        let mut conn = self.conn.borrow_mut();
        let key = format!("refresh_token:{}", token);
        let value = serde_json::json!({
            "client_id": client_id,
            "user_id": user_id,
            "exp": exp,
        });
        conn.set_ex::<_, _, ()>(key, value.to_string(), exp as usize)
            .unwrap();
        Ok(())
    }

    fn revoke_refresh_token(&mut self, token: &str) -> bool {
        let mut conn = self.conn.borrow_mut(); // Mutably borrow the Redis connection for the `sadd` operation
        let result: Result<(), RedisError> = conn.sadd("revoked_refresh_tokens", token);

        if let Err(err) = result {
            eprintln!("Error revoking refresh token: {}", err);
            false
        } else {
            true
        }
    }

    fn validate_refresh_token(
        &mut self,
        token: &str,
        client_id: &str,
    ) -> Result<(String, u64), TokenError> {
        let mut conn = self.conn.borrow_mut();
        let key = format!("refresh_token:{}", token);
        let result: Option<String> = conn.get(&key).unwrap();

        if let Some(data) = result {
            let parsed: serde_json::Value = serde_json::from_str(&data).unwrap();
            let stored_client_id = parsed["client_id"].as_str().unwrap().to_string(); // Convert to String
            let exp = parsed["exp"].as_u64().unwrap();

            if stored_client_id == client_id.to_string() {
                Ok((stored_client_id, exp))
            } else {
                Err(TokenError::InvalidClient)
            }
        } else {
            Err(TokenError::InvalidToken)
        }
    }

    fn is_refresh_token_revoked(&self, token: &str) -> bool {
        let mut conn = self.conn.borrow_mut();
        conn.sismember("revoked_refresh_tokens", token)
            .unwrap_or(false)
    }

    // Check if an access or refresh token is revoked
    fn is_token_revoked(&self, token: &str) -> bool {
        let mut conn = self.conn.borrow_mut(); // Mutably borrow the Redis connection for the `sismember` operation
        let access_revoked: bool = conn
            .sismember("revoked_access_tokens", token)
            .unwrap_or(false);
        let refresh_revoked: bool = conn
            .sismember("revoked_refresh_tokens", token)
            .unwrap_or(false);

        access_revoked || refresh_revoked
    }

    fn rotate_refresh_token(
        &mut self,
        old_token: &str,
        new_token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError> {
        {
            let mut conn = self.conn.borrow_mut();
        }
        // Revoke the old refresh token
        if !self.revoke_refresh_token(old_token) {
            return Err(TokenError::InvalidToken);
        }
        // Store the new refresh token
        self.store_refresh_token(new_token, client_id, user_id, exp)
    }
}

/// Redis storage backend for client credentials.
pub struct RedisStorage {
    pub redis_client: Client,
}

impl RedisStorage {
    /// Initialize a new Redis storage backend.
    pub fn new(redis_url: &str) -> Result<Self, RedisError> {
        let client = Client::open(redis_url)?;
        Ok(RedisStorage {
            redis_client: client,
        })
    }
}

impl StorageBackend for RedisStorage {
    fn get_client_by_id(&self, client_id: &str) -> Result<Option<ClientData>, OAuthError> {
        let mut conn = self
            .redis_client
            .get_connection()
            .map_err(|_| OAuthError::TokenGenerationError)?;

        // Fetch client information from Redis (assuming it's stored as a hash)
        let secret: String = conn.hget(client_id, "secret").unwrap_or_default();
        let scopes: String = conn.hget(client_id, "scopes").unwrap_or_default(); // Scopes could be comma-separated

        if secret.is_empty() {
            return Ok(None); // Client not found
        }

        let client_data = ClientData {
            client_id: client_id.to_string(),
            secret,
            allowed_scopes: scopes.split(',').map(String::from).collect(),
        };

        Ok(Some(client_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::{Client, Commands};

    fn setup_redis_connection() -> Connection {
        let client = Client::open("redis://127.0.0.1/").unwrap();
        client.get_connection().unwrap()
    }

    #[test]
    fn test_store_and_retrieve_authorization_code() {
        let conn = setup_redis_connection();
        let mut code_store = RedisCodeStore::new(conn);

        let code = AuthorizationCode {
            code: "auth_code_123".to_string(),
            client_id: "client_id_123".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            pkce_challenge: "challenge_123".to_string(),
            scope: "read".to_string(),
            expires_at: std::time::SystemTime::now(),
        };

        code_store.store_code(code.clone());

        let retrieved_code = code_store.retrieve_code("auth_code_123").unwrap();
        assert_eq!(retrieved_code.code, code.code);
        assert_eq!(retrieved_code.client_id, code.client_id);

        code_store.revoke_code("auth_code_123");
        assert!(code_store.is_code_revoked("auth_code_123"));
        assert!(code_store.retrieve_code("auth_code_123").is_none());
    }

    #[test]
    fn test_revoke_token() {
        let conn = setup_redis_connection();
        let mut token_store = RedisTokenStore::new(conn);

        let access_token = "access_token_123";
        let refresh_token = "refresh_token_123";

        token_store.revoke_access_token(access_token);
        assert!(token_store.is_token_revoked(access_token));

        token_store.revoke_refresh_token(refresh_token);
        assert!(token_store.is_token_revoked(refresh_token));
    }
}
