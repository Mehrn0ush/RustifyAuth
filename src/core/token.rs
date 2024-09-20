use jsonwebtoken::{decode, encode, Header, EncodingKey, Algorithm, DecodingKey, Validation, TokenData};
use rand::{Rng, thread_rng};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use rand::distributions::Alphanumeric;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use crate::core::types::{TokenError, TokenResponse, TokenRequest};
use crate::core::authorization::AuthorizationCodeFlow;
use crate::security::rate_limit::RateLimiter;
use crate::storage::memory::TokenStore as MemoryTokenStore;
use crate::storage::memory::TokenStore as StorageTokenStore;

use redis::{Commands, Connection};
use redis::Client;
use dotenv::dotenv;
use std::env;


pub struct RedisTokenStore {
    conn: Arc<Mutex<Connection>>,
}

impl RedisTokenStore {
    pub fn new(client: &Client) -> Result<Self, TokenError> {
        let conn = client.get_connection().map_err(|_| TokenError::InternalError)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl TokenStore for RedisTokenStore {


    fn store_refresh_token(&self, token: &str, client_id: &str, user_id: &str, exp: u64) -> Result<(), TokenError> {
        let mut conn = self.conn.lock().map_err(|_| TokenError::InternalError)?;
        let key = format!("refresh_token:{}", token);
        let value = serde_json::to_string(&(client_id, user_id)).map_err(|_| TokenError::InternalError)?;
        conn.set_ex(key, value, (exp - get_current_time()?) as usize).map_err(|_| TokenError::InternalError)?;
        Ok(())
    }

    fn validate_refresh_token(&self, token: &str, client_id: &str) -> Result<(String, u64), TokenError> {
        let mut conn = self.conn.lock().map_err(|_| TokenError::InternalError)?;
        let key = format!("refresh_token:{}", token);
        let result: Option<String> = conn.get(&key).map_err(|_| TokenError::InternalError)?;
        if let Some(value) = result {
            let (stored_client_id, user_id): (String, String) = serde_json::from_str(&value).map_err(|_| TokenError::InvalidToken)?;
            if stored_client_id == client_id {
                // Get the token's expiration time
                let ttl: usize = conn.ttl(&key).map_err(|_| TokenError::InternalError)?;
                let exp = get_current_time()? + ttl as u64;
                Ok((user_id, exp))
            } else {
                Err(TokenError::InvalidClient)
            }
        } else {
            Err(TokenError::InvalidToken)
        }
    }

    
    fn revoke_token(&self, token: String, exp: u64) -> Result<(), TokenError> {
        let now = get_current_time()?;
        
        if is_token_expired(exp, now) {
            println!("Token {} has already expired, skipping revocation.", token);
            return Ok(());  // Token is expired, so no need to revoke
        }

        let ttl = calculate_ttl(exp, now);
        self.store_revoked_token(token, ttl)
    }

    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError> {
        let mut conn = self.conn.lock().unwrap_or_else(|poisoned| {
            eprintln!("Redis connection mutex was poisoned: {:?}", poisoned);
            poisoned.into_inner()
        });
        
        let result: Option<String> = conn.get(token).map_err(|_| TokenError::InternalError)?;
        Ok(result.as_deref() == Some("revoked"))
    }

    fn cleanup_expired_tokens(&self) -> Result<(), TokenError> {
        println!("Redis automatically cleans up expired tokens.");
        Ok(())
    }


}



fn calculate_ttl(exp: u64, now: u64) -> usize {
    exp.saturating_sub(now) as usize
}

impl RedisTokenStore {
    fn store_revoked_token(&self, token: String, ttl: usize) -> Result<(), TokenError> {
        let mut conn = self.conn.lock().unwrap_or_else(|poisoned| {
            eprintln!("Redis connection mutex was poisoned: {:?}", poisoned);
            poisoned.into_inner()
        });

        conn.set_ex(token.clone(), "revoked", ttl).map_err(|e| {
            eprintln!("Failed to store revoked token {} in Redis: {:?}", token, e);
            TokenError::InternalError
        })?;

        println!("Revoked token in Redis: {}, TTL: {}", token, ttl);
        Ok(())
    }
    

    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError> {
        // Handle possible errors when locking the connection and retrieving the token status.
        let mut conn = self.conn.lock().map_err(|_| TokenError::InternalError)?;  // Lock the connection
        let result: Option<String> = conn.get(token).map_err(|_| TokenError::InternalError)?;  // Get token status
        Ok(result.as_deref() == Some("revoked"))  // Return true if the token is revoked
    }

    fn cleanup_expired_tokens(&self) -> Result<(), TokenError> {
        // Redis automatically handles expired keys, so no manual cleanup is needed.
        println!("Redis automatically cleans up expired tokens.");
        Ok(())
    }
    
}
pub trait TokenStore: Send + Sync {
    fn store_refresh_token(&self, token: &str, client_id: &str, user_id: &str, exp: u64) -> Result<(), TokenError>;
    fn revoke_token(&self, token: String, exp: u64) -> Result<(), TokenError>;
    fn validate_refresh_token(&self, token: &str, client_id: &str) -> Result<(String, u64), TokenError>;
    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError>;
    fn cleanup_expired_tokens(&self) -> Result<(), TokenError>;  // Regularly clean up expired tokens
}

pub struct InMemoryTokenStore {
    revoked_tokens: Mutex<HashMap<String, u64>>,  // Token -> Expiration timestamp
}

impl InMemoryTokenStore {

    // Constructor method for InMemoryTokenStore
    pub fn new() -> Self {
        Self {
            revoked_tokens: Mutex::new(HashMap::new()),  // Initialize the revoked_tokens HashMap
        }
    }
    fn get_revoked_tokens(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, u64>>, TokenError> {
        self.revoked_tokens.lock().map_err(|e| {
            eprintln!("Failed to acquire lock on revoked_tokens: {:?}", e);
            TokenError::InternalError
        })
    }
}

// Helper function for retrieving the current time
fn get_current_time() -> Result<u64, TokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| {
            eprintln!("Failed to retrieve current time: {:?}", e);
            TokenError::InternalError
        })
}

// Helper function to check if the token is expired
fn is_token_expired(exp: u64, now: u64) -> bool {
    exp <= now
}

impl TokenStore for InMemoryTokenStore {

    fn store_refresh_token(&self, token: &str, client_id: &str, user_id: &str, exp: u64) -> Result<(), TokenError> {
        let mut revoked_tokens = self.get_revoked_tokens()?;
        revoked_tokens.insert(token.to_string(), exp);
        Ok(())
    }

    fn validate_refresh_token(&self, token: &str, client_id: &str) -> Result<(String, u64), TokenError> {
        let revoked_tokens = self.get_revoked_tokens()?;
        if let Some(&exp) = revoked_tokens.get(token) {
            if exp > get_current_time()? {
                // For InMemory store, you can return the user_id associated with the token
                // Modify the store to keep track of (token, (client_id, user_id, exp))
                Ok((String::from("user_id_placeholder"), exp))
            } else {
                Err(TokenError::ExpiredToken)
            }
        } else {
            Err(TokenError::InvalidToken)
        }
    }
    fn revoke_token(&self, token: String, exp: u64) -> Result<(), TokenError> {
        let now = get_current_time()?;

        if is_token_expired(exp, now) {
            println!("Token {} has already expired.", token);
            return Err(TokenError::ExpiredToken);  // Log expired tokens and return an error
        }

        let mut revoked_tokens = self.get_revoked_tokens()?;
        revoked_tokens.insert(token.clone(), exp);
        println!("Revoked token: {}, exp: {}", token, exp);
        Ok(())
    }

    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError> {
        let revoked_tokens = self.get_revoked_tokens()?;

        if let Some(&exp) = revoked_tokens.get(token) {
            let now = get_current_time()?;

            println!("Token: {}, Exp: {}, Now: {}", token, exp, now);

            if exp > now {
                println!("Token {} is still revoked and valid until {}", token, exp);
                return Ok(true);
            } else {
                println!("Token {} has already expired.", token);
            }
        } else {
            println!("Token {} was not found in revoked_tokens.", token);
        }

        Ok(false)
    }

    fn cleanup_expired_tokens(&self) -> Result<(), TokenError> {
        let mut revoked_tokens = self.get_revoked_tokens()?;
        let now = get_current_time()?;

        println!("Cleaning up expired tokens. Current time: {}", now);

        revoked_tokens.retain(|token, &mut exp| {
            let is_valid = exp > now;
            if !is_valid {
                println!("Removing expired token: {}", token);
            }
            is_valid
        });

        Ok(())
    }
}


// Helper function for getting token

    fn get_token_config() -> (Option<String>, String, String) {
        dotenv().ok(); // Load the .env file

        let audience = env::var("TOKEN_AUDIENCE").ok(); // Option<String>

        let subject = env::var("TOKEN_SUBJECT")
            .unwrap_or_else(|_| "default_subject".to_string()); // Default value for subject

        let required_scope = env::var("TOKEN_SCOPE")
            .unwrap_or_else(|_| "default_scope".to_string()); // Default value for scope

        (audience, subject, required_scope)
    }



// TokenGenerator trait defines a contract for generating access and refresh tokens
pub trait TokenGenerator {
    fn access_token_lifetime(&self) -> Duration;
    fn generate_access_token(&self, client_id: &str, user_id: &str, scope: &str) -> Result<String, TokenError>;
    fn generate_refresh_token(&self, client_id: &str, user_id: &str, scope: &str) -> Result<String, TokenError>;
    fn validate_token(
        &self, 
        token: &str, 
        expected_aud: Option<&str>, 
        expected_sub: &str, 
        required_scope: &str
    ) -> Result<TokenData<Claims>, TokenError>; // Leave as a trait method signature

    fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<(String, String), TokenError>; // Add this method to the trait

}



#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub scope: Option<String>,
    pub aud: Option<String>,
    pub client_id: Option<String>,
    pub iat: u64,
    pub iss: Option<String>,
}





// JWT token generator using RS256
pub struct JwtTokenGenerator {
    pub private_key: Vec<u8>, // RS256 private key for JWT
    pub public_key: Vec<u8>, // RS256 public key for JWT validation
    pub issuer: String,       // Token issuer (for claim)
    pub access_token_lifetime: Duration, // Access token validity duration
    pub refresh_token_lifetime: Duration, // Refresh token validity duration
    pub token_store: Arc<dyn TokenStore>,
   // pub revoked_tokens: Mutex<HashSet<String>>, // Store revoked tokens
}

impl JwtTokenGenerator {
    // Constructor for JwtTokenGenerator
    pub fn new(
        private_key: Vec<u8>, 
        public_key: Vec<u8>,
        issuer: String, 
        access_token_lifetime: Duration, 
        refresh_token_lifetime: Duration, 
        token_store: Arc<dyn TokenStore>
    ) -> Self {
        JwtTokenGenerator {
            private_key,
            public_key,
            issuer,
            access_token_lifetime,
            refresh_token_lifetime,
            token_store,
        }
    }

    // Exchange refresh token and rotate refresh token as per OAuth 2.0 security best practices
    pub fn exchange_refresh_token(
    &self,
    refresh_token: &str,
    client_id: &str,
    scope: &str,
) -> Result<(String, String), TokenError> {
    // Step 1: Validate the refresh token and get the user_id and expiration time
    let (user_id, exp) = self.token_store.validate_refresh_token(refresh_token, client_id)?;

    // Step 2: Revoke the old refresh token using the expiration time
    self.token_store.revoke_token(refresh_token.to_string(), exp)?;

    // Step 3: Generate a new access token
    let access_token = self.generate_access_token_internal(client_id, &user_id, scope)?;

    // Step 4: Generate a new refresh token
    let new_refresh_token = self.generate_refresh_token_internal(client_id, &user_id, scope)?;

    // Step 5: Store the new refresh token with the updated expiration time
    let new_exp = get_current_time()? + self.refresh_token_lifetime.as_secs();
    self.token_store.store_refresh_token(&new_refresh_token, client_id, &user_id, new_exp)?;

    Ok((access_token, new_refresh_token))
}


    // Helper function to sign JWT tokens
    fn sign_token(&self, claims: &Claims) -> Result<String, TokenError> {
        let header = Header::new(Algorithm::RS256);
        println!("Signing JWT token with RS256 algorithm.");
        
        let encoding_key = EncodingKey::from_rsa_pem(&self.private_key).map_err(|e| {
            println!("Error loading private key for signing: {:?}", e);
            TokenError::InternalError
        })?;
        
        encode(&header, &claims, &encoding_key).map_err(|e| {
            println!("Error signing token: {:?}", e);
            TokenError::InternalError
        })
    }

    // Helper method to extract token expiration
    pub fn get_token_exp(&self, token: &str) -> Result<u64, TokenError> {
        let decoding_key = DecodingKey::from_rsa_pem(&self.public_key).map_err(|e| {
            println!("Error loading public key for decoding: {:?}", e);
            TokenError::InternalError
        })?;        
        let token_data = decode::<Claims>(token, &decoding_key, &Validation::new(Algorithm::RS256))
            .map_err(|_| TokenError::InvalidToken)?;

        Ok(token_data.claims.exp)
    }

    // Helper function to generate claims for JWT access token
    fn create_claims(&self, client_id: &str, user_id: &str, expiration: Duration, scope: &str) -> Result<Claims, TokenError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| TokenError::InternalError)?
            .as_secs() as usize;


        Ok(Claims {
            sub: user_id.to_owned(),
            client_id: Some(client_id.to_owned()),
            exp: now as u64 + expiration.as_secs(),
            iat: now as u64,
            iss: Some(self.issuer.clone()),
            aud: None, // Optional audience
            scope: Some(scope.to_owned()),
        })
    }

    // Generate an access token
    pub fn generate_access_token_internal(&self, client_id: &str, user_id: &str, scope: &str) -> Result<String, TokenError> {
        let claims = self.create_claims(client_id, user_id, self.access_token_lifetime, scope)?;
        self.sign_token(&claims)
    }

    // Generate a refresh token
    pub fn generate_refresh_token_internal(&self, client_id: &str, user_id: &str, scope: &str) -> Result<String, TokenError> {
        let claims = self.create_claims(client_id, user_id, self.refresh_token_lifetime, scope)?;
        self.sign_token(&claims)
    }

    // Validate JWT claims for access token
    pub fn validate_token(
        &self, 
        token: &str, 
        expected_aud: Option<&str>, 
        expected_sub: &str, 
        required_scope: &str
    ) -> Result<TokenData<Claims>, TokenError> {
        println!("Validating token: {}", token);
        
        // Decode the token and check for expiration
        let decoding_key = DecodingKey::from_rsa_pem(&self.public_key).map_err(|e| {
            println!("Error loading public key for validation: {:?}", e);
            TokenError::InternalError
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;  // Ensure expiration is checked
        validation.leeway = 5; // Allow 5 seconds of leeway

        
        let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|err| {
            println!("Error decoding token: {:?}", err);
            match *err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    println!("Token signature is invalid.");
                    TokenError::InvalidSignature
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    println!("Token has expired.");
                    TokenError::ExpiredToken
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_)
                | jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey
                | jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName
                | jsonwebtoken::errors::ErrorKind::Base64(_)
                | jsonwebtoken::errors::ErrorKind::Json(_)
                | jsonwebtoken::errors::ErrorKind::Utf8(_) => {
                    println!("Token decoding failed due to invalid format.");
                    TokenError::InvalidToken
                }
                _ => {
                    println!("Token validation failed due to an unknown error.");
                    TokenError::InvalidGrant
                }
            }
        })?;

        // Check if the token is revoked
        if self.token_store.is_token_revoked(token)? {
            println!("Token {} is revoked.", token);
            return Err(TokenError::InvalidGrant);
        }

        // Validate the required scope
        let token_scopes: HashSet<String> = token_data
            .claims
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if !token_scopes.contains(required_scope) {
            println!("Token is missing the required scope: {}", required_scope);
            return Err(TokenError::InsufficientScope);
        }

        // Validate subject
        if token_data.claims.sub != expected_sub {
            println!("Token subject mismatch: expected {}, got {}", expected_sub, token_data.claims.sub);
            return Err(TokenError::InvalidGrant);
        }

        println!("Token {} successfully validated.", token);
        Ok(token_data)
    }

    // Revoke a JWT access token
    fn revoke_jwt_access_token(&self, token: &str) -> Result<(), TokenError> {
        let exp = self.get_token_exp(token)?;  // Get token expiration time
        // Revoke the JWT access token
        self.token_store.revoke_token(token.to_string(), exp)?;


        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TokenError::InternalError)?
            .as_secs();

        println!("Current time (now): {}", now);

        if exp <= now {
            println!("Token has already expired.");
            return Err(TokenError::ExpiredToken);  // Return ExpiredToken error
        }

        self.token_store.revoke_token(token.to_string(), exp)
    }
}

// TokenRevocation trait to handle token revocation
pub trait TokenRevocation {
    fn revoke_access_token(&self, token: &str) -> Result<(), TokenError>;
    fn revoke_refresh_token(&self, token: &str) -> Result<(), TokenError>;
}

// Implement TokenRevocation for JwtTokenGenerator
impl TokenRevocation for JwtTokenGenerator {
    fn revoke_access_token(&self, token: &str) -> Result<(), TokenError> {
        println!("Attempting to revoke access token: {}", token);

        // Step 1: Get the expiration time of the token
        let exp = self.get_token_exp(token)?;
        println!("Access token expiration time (exp): {}", exp);

        // Step 2: Get the current system time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TokenError::InternalError)?
            .as_secs();
        println!("Current system time (now): {}", now);

        // Step 3: Check if the token has already expired
        if exp <= now {
            println!("Access token {} has already expired.", token);
            return Err(TokenError::ExpiredToken);  // Return an error indicating the token is already expired
        }

        // Step 4: Proceed with revoking the token
        self.token_store
            .revoke_token(token.to_string(), exp)
            .map_err(|e| {
                println!("Error revoking access token {}: {:?}", token, e);
                TokenError::InternalError
            })
            .map(|_| {
                println!("Access token {} revoked successfully.", token);
            })
    }

    fn revoke_refresh_token(&self, token: &str) -> Result<(), TokenError> {
        println!("Attempting to revoke refresh token: {}", token);

        // Step 1: Get the expiration time of the refresh token
        let exp = self.get_token_exp(token)?;
        println!("Refresh token expiration time (exp): {}", exp);

        // Step 2: Revoke the refresh token
        self.token_store
            .revoke_token(token.to_string(), exp)
            .map_err(|e| {
                println!("Error revoking refresh token {}: {:?}", token, e);
                TokenError::InternalError
            })
            .map(|_| {
                println!("Refresh token {} revoked successfully.", token);
            })
    }
}

// Implement TokenGenerator for JwtTokenGenerator
impl TokenGenerator for JwtTokenGenerator {
    fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<(String, String), TokenError> {
        // Step 1: Validate the refresh token
        let (user_id, _) = self.token_store.validate_refresh_token(refresh_token, client_id)?;

        // Step 2: Revoke the old refresh token
        self.token_store.revoke_token(refresh_token.to_string(), self.refresh_token_lifetime.as_secs())?;

        // Step 3: Generate a new access token
        let access_token = self.generate_access_token_internal(client_id, &user_id, scope)?;

        // Step 4: Generate a new refresh token
        let new_refresh_token = self.generate_refresh_token_internal(client_id, &user_id, scope)?;

        // Step 5: Store the new refresh token
        let exp = get_current_time()? + self.refresh_token_lifetime.as_secs();
        self.token_store.store_refresh_token(&new_refresh_token, client_id, &user_id, exp)?;

        Ok((access_token, new_refresh_token))
    }
    fn access_token_lifetime(&self) -> Duration {
        self.access_token_lifetime
    }
    fn generate_access_token(&self, client_id: &str, user_id: &str, scope: &str) -> Result<String, TokenError> {
        self.generate_access_token_internal(client_id, user_id, scope)
    }

    fn generate_refresh_token(&self, client_id: &str, user_id: &str, scope: &str) -> Result<String, TokenError> {
        self.generate_refresh_token_internal(client_id, user_id, scope)
    }

    fn validate_token(
        &self, 
        token: &str, 
        expected_aud: Option<&str>, 
        expected_sub: &str, 
        required_scope: &str
    ) -> Result<TokenData<Claims>, TokenError> {
        println!("Validating token: {}", token);

        // Step 1: Decode the token to check expiration and validity
        let decoding_key = DecodingKey::from_rsa_pem(&self.public_key)
            .map_err(|e| {
                println!("Error loading public key for validation: {:?}", e);
                TokenError::InternalError
            })?;
        
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;  // Ensure expiration is checked
        validation.leeway = 5; // Allow 5 seconds of leeway

        
        let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|err| {
            println!("Error decoding token: {:?}", err);
            match *err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    println!("Token has expired.");
                    TokenError::ExpiredToken
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    println!("Token signature is invalid.");
                    TokenError::InvalidSignature
                }
                _ => {
                    println!("Token validation failed due to an unknown error.");
                    TokenError::InvalidGrant
                }
            }
            
        })?;

        // Step 2: Check if the token is revoked
        if self.token_store.is_token_revoked(token)? {
            println!("Token {} is revoked.", token);
            return Err(TokenError::InvalidGrant);
        }

        // Step 3: Validate the required scope
        let token_scopes: HashSet<String> = token_data
            .claims
            .scope
            .as_ref()  // Borrow the value instead of moving it
            .map(|scope| scope.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_else(HashSet::new);  // Handle `None` safely by providing an empty set

        if !token_scopes.contains(required_scope) {
            println!("Token is missing the required scope: {}", required_scope);
            return Err(TokenError::InsufficientScope);
        }

        // Step 4: Check subject
        if token_data.claims.sub != expected_sub {
            println!("Token subject mismatch: expected {}, got {}", expected_sub, token_data.claims.sub);
            return Err(TokenError::InvalidGrant);
        }

        println!("Token {} successfully validated.", token);
        Ok(token_data)
    }
}



// Opaque token generator using random strings
pub struct OpaqueTokenGenerator {
    token_length: usize, // Length of the random token
}

impl OpaqueTokenGenerator {
    // Helper function to generate a random opaque token
    fn generate_random_token(&self) -> String {
        // Ensure the randomness is sufficient by checking token length
        assert!(self.token_length > 0, "Token length must be greater than 0");

        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(self.token_length)
            .map(char::from)
            .collect()
    }

    // Opaque access token generation
    fn generate_access_token_internal(&self) -> Result<String, TokenError> {
        let token = self.generate_random_token();
        println!("Generated opaque access token: {}", token);
        Ok(token)
    }

    // Opaque refresh token generation
    fn generate_refresh_token_internal(&self) -> Result<String, TokenError> {
        let token = self.generate_random_token();
        println!("Generated opaque refresh token: {}", token);
        Ok(token)
    }
}
// Implement TokenGenerator for OpaqueTokenGenerator
impl TokenGenerator for OpaqueTokenGenerator {
    fn access_token_lifetime(&self) -> Duration {
        // Return a default lifetime for opaque tokens (e.g., 1 hour)
        Duration::from_secs(3600)  // 1 hour
    }

    // Handle refresh token exchange for opaque tokens
    fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<(String, String), TokenError> {
        // In this case, we may not need to handle refresh tokens for opaque tokens,
        // but here is a placeholder to comply with the trait.

        // Step 1: Normally, we would validate the refresh token, but opaque tokens may not support it.
        println!("Opaque tokens do not support refresh token exchange.");
        Err(TokenError::UnsupportedOperation)  // Returning an error because it's not supported.
    }

    fn validate_token(
        &self, 
        _token: &str, 
        _expected_aud: Option<&str>, 
        _expected_sub: &str, 
        _required_scope: &str
    ) -> Result<TokenData<Claims>, TokenError> {
        // Opaque tokens do not carry claims or support validation like JWT tokens.
        // Hence, this operation is not supported for opaque tokens.
        println!("Opaque tokens do not support validation.");
        Err(TokenError::UnsupportedOperation) // Use a specific error to indicate unsupported operation
    }

    fn generate_access_token(&self, _client_id: &str, _user_id: &str, _scope: &str) -> Result<String, TokenError> {
        println!("Generating opaque access token.");
        self.generate_access_token_internal()
    }

    fn generate_refresh_token(&self, _client_id: &str, _user_id: &str, _scope: &str) -> Result<String, TokenError> {
        println!("Generating opaque refresh token.");
        self.generate_refresh_token_internal()
    }
}
// Token endpoint for handling token requests
pub async fn token_endpoint(
    req: TokenRequest,
    auth_code_flow: Arc<Mutex<AuthorizationCodeFlow>>,  // For Authorization Code Flow
    rate_limiter: Arc<RateLimiter>,                     // To protect against rate limiting
    token_generator: Arc<dyn TokenGenerator>,           // Token generation (JWT, Opaque)
    token_store: Arc<dyn TokenStore>,                   // Token Store (In-Memory, Redis)
) -> Result<TokenResponse, TokenError> {

    // Step 1: Validate common fields depending on the grant type
    match req.grant_type.as_str() {
        "authorization_code" => {
            // Validate required fields for authorization_code grant
            if req.code.as_deref().unwrap_or("").is_empty() || req.client_id.is_empty() || req.pkce_verifier.as_deref().unwrap_or("").is_empty() {
                println!("Missing required fields in the token request.");
                return Err(TokenError::MissingFields);
            }            
        },
        "refresh_token" => {
            // Validate required fields for refresh_token grant
            if req.refresh_token.is_none() || req.client_id.is_empty() {
                println!("Missing required fields for refresh_token grant.");
                return Err(TokenError::MissingFields);
            }
        },
        "client_credentials" => {
            // Validate fields for client_credentials grant (e.g., client_id, client_secret)
            if req.client_id.is_empty() || req.client_secret.is_none() {
                println!("Missing required fields for client_credentials grant.");
                return Err(TokenError::MissingFields);
            }
        },
        _ => return Err(TokenError::UnsupportedGrantType),  // Unsupported grant type
    }

    // Step 2: Check if the client is rate-limited
    if rate_limiter.is_rate_limited(&req.client_id) {
        println!("Rate limit exceeded for client: {}", req.client_id);
        return Err(TokenError::RateLimited);
    }

    // Step 3: Handle different grant types
    match req.grant_type.as_str() {
        "authorization_code" => {
            // Lock the AuthorizationCodeFlow for safe access
            let mut auth_code_flow = auth_code_flow.lock().map_err(|_| {
                println!("Failed to lock auth_code_flow.");
                TokenError::InternalError
            })?;

            // Exchange authorization code for tokens (access & refresh)
            let token_response = auth_code_flow
                .exchange_code_for_token(
                    &req.code.as_deref().unwrap_or(""), 
                    &req.pkce_verifier.as_deref().unwrap_or("")
                )
                .map_err(|e| {
                    println!("Error exchanging authorization code for tokens: {:?}", e);
                    TokenError::InvalidGrant
                })?;

            println!("Authorization Code grant successful for client: {}", req.client_id);
            Ok(token_response)
        },
        "refresh_token" => {
            // Handle refresh token flow
            let refresh_token = req.refresh_token.as_ref().unwrap();
            let scope = req.scope.as_deref().unwrap_or("default_scope");

            // Rotate refresh tokens and issue new access token
            let (access_token, new_refresh_token) = token_generator.exchange_refresh_token(
                refresh_token,
                &req.client_id,
                scope,
            )?;

            println!("Refresh Token grant successful for client: {}", req.client_id);
            Ok(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: token_generator.access_token_lifetime().as_secs(),  // Fix type here
                refresh_token: new_refresh_token,  // Fix type here
                scope: Some(scope.to_string()),  // Add scope here
            })
        },
        "client_credentials" => {
            // Handle client_credentials flow (no user, just client)
            let scope = req.scope.as_deref().unwrap_or("default_scope");

            // Generate access token directly for the client
            let access_token = token_generator.generate_access_token(
                &req.client_id,
                "client_credentials_user",  // Placeholder user
                scope,
            )?;

            println!("Client Credentials grant successful for client: {}", req.client_id);
            Ok(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: token_generator.access_token_lifetime().as_secs(),  // Fix type here
                refresh_token: "".to_string(),  // No refresh token in client_credentials flow
                scope: Some(scope.to_string()),  // Add scope here
            })
        },
        _ => {
            // Unsupported grant type (already checked earlier)
            println!("Unsupported grant type: {}", req.grant_type);
            Err(TokenError::UnsupportedGrantType)
        }
    }
}








#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::sync::Arc;
    use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

    
    // Sample RSA private key for signing JWT (for testing purposes)
    const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJXp73fXFw3jjR
c4PmkhqtVgBtX4gRodEr+iSEDbmW5A7YUuQfmKHEly5IZypnpc0pD25ftEfademm
yj4h8xRhkkgOsvlrTgYegjNSGq4dA4q9GpJuzlHBf4hPYP4H/1obcKD6hOszT9MR
EFFLQzU8O6G8nTTm0uWRGlpQ8kEmkb7NDDh9B8ZV1O3Gt1nSax/3xEnclDiz73Ix
p+qwlk1T2c28Msu+mNaq+W9nsiA4fcXb2iCuWbuo1k0bV1qtPlDclrr8ne9SfBBf
aJDmDbL6W2ST6qx5pUiJpzYBtVvGoeRlKwBx0dDv3/NrrFmevRlSOo6ONfXLIf0w
5NgAxRg7AgMBAAECggEAG2DkjzS8jEKCiiPBDsPVobScOUKwXulX5blMZrHxBk16
oTnf71XSxMZjUg/Iya/WzZreAGAkFtVKT9WWjgodPsjjSDBYThkdJt+/941OF/7H
yb9Hoo4lun/K+jPvRgoXZ7yv/m+9BMx5H4xO6UM5hTd8XYcoTqvk744cMn5Fkmcn
V3pbmibEZRFCXrGFhchT42KL/S/A5RSFoKl0bF+IWQafu0zMPdhCx6eembvihZHr
jSawZHgXlHSnb/IpI71fPMN51NsWt9fpKz1CjSiZhhyEZtsEpSGNg52K+uldYDZy
XjYyOlGmzrf5HIEhXQYIBwg4ll138mr9VFOg1q6vFQKBgQD/HWXZnjUQVzx5eQSE
3vuIN1B5CQmXzxLXtLK18opogtXtQ2n7p2WRM95unfY31b7eTyvvtNmAozurIC87
6O3GrtD66v0kosV+1dt6rqiRKjw6Y5u8MFZpQaWyrsGLOm1EK3LgdQ7IpTL6hElz
vawlcDwmahryQD0ZOdzJkDL5JwKBgQDKEXwT12K/iaUgSJZ0YVGUSJ7tzvAO1a4k
DqG2uPZltm0bpMxUwyoeAb7muDkxTdxOanEJtdeC50IeQ8xPfv0JRu8XGOnZsyg1
04wzwNmgqjYMSMY9lJ5V6ud7EL+L1llML2rqFtLUkRl9rk6TPzBwf3w9zf/pjzSY
XepUj6RMzQKBgAI4BTzBTYDY4WPFE678KX/jy0ViOL0jReyuW6eNdnq2OJoZrgBM
UmvS4apgoVWW/FP+qEkrb4DY6pnwa7i/q+HAf3zPMmhxKfqSbZhBkKHClkeDukUG
vpmnwoMtVe2aEn03S4Z8PiasmSboo6LoEWk58qv63EUjHeTsRelS4b6dAoGBAKjf
sfWXFQUEUQdJAsyipJ4rjv8p6gBL3mxt+gKOVAYvTsJCmS3hqWpIhTWnEs08x/iV
BoFaApF5Gg3XFYH+nBRLvvdrr8xr6RgLA2ohKwAWIHNlwp+mfClL10dHeP2yFxEP
s+eNSYey+D3MFgkDT0VFlhzE87JLJ2aLXpJrNaGlAoGASi2AOMgACBRR+JgX9c35
9FhvuVf21qbZ2Dxeh5CEHL/f7F+LTM7+LjhDG2o1L5hHe1uMUZPYeilUYq67FpKO
r9BLaYDADOnT9wRoNyMZNe1k2GXhO0hYrCUNvpTg/Ts3A1lkAN/lBIN+8W2XVOt8
8unIP9lpK/281TICH2mivV8=
-----END PRIVATE KEY-----
";
    const RSA_PUBLIC_KEY: &str = "
    -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyV6e931xcN440XOD5pIa
rVYAbV+IEaHRK/okhA25luQO2FLkH5ihxJcuSGcqZ6XNKQ9uX7RH2nXppso+IfMU
YZJIDrL5a04GHoIzUhquHQOKvRqSbs5RwX+IT2D+B/9aG3Cg+oTrM0/TERBRS0M1
PDuhvJ005tLlkRpaUPJBJpG+zQw4fQfGVdTtxrdZ0msf98RJ3JQ4s+9yMafqsJZN
U9nNvDLLvpjWqvlvZ7IgOH3F29ogrlm7qNZNG1darT5Q3Ja6/J3vUnwQX2iQ5g2y
+ltkk+qseaVIiac2AbVbxqHkZSsAcdHQ79/za6xZnr0ZUjqOjjX1yyH9MOTYAMUY
OwIDAQAB
-----END PUBLIC KEY-----
    ";

    // Sample RSA public key corresponding to the private key (for testing purposes)
const wrong_RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0dfYZcSUHThNpuIW0ZB+
jMjxA+GgfTe1d0LkWk3P8N5iIdnBsS8L+xFd5dXYxv6UeH2jx5jG/rHo5oUpUunP
D9HJl7YPyAa2oavmsPY9mvHjPzj1fNR2NC8nZdDSVIBkEYcyb9jQsDxmgXAdfbLt
nRJhWvdLONmlBik6JKlLKDi6zZTQ+bt/ZHVf8LRySOyxOL0Qd+azVshJoYeTSYhx
RnbhMLYrW3yUP+3MPMN02oKXDC3dx7Lf5gUXy/7Gmp/X1vXDeqxokpDtQdmJ5/QU
kG7QKzUQ3ttxLp6msF5AzoUdACoVaCzYtbyw1TGb/ZmK6BtHJbZwP4TFKNcCdt8/
cwIDAQAB
-----END PUBLIC KEY-----";

fn setup_jwt_generator_with_short_expiry() -> JwtTokenGenerator {
    let private_key = RSA_PRIVATE_KEY.as_bytes().to_vec();
    let public_key = RSA_PUBLIC_KEY.as_bytes().to_vec();
    let issuer = "test-issuer".to_string();

    // Short expiration time (1 second) for testing
    let access_lifetime = Duration::from_secs(1);  // 1 second expiration
    let refresh_lifetime = Duration::from_secs(2); // 2 seconds expiration

    let token_store = Arc::new(InMemoryTokenStore::new());

    // Call the `new` function with the correct number of arguments
    JwtTokenGenerator::new(
        private_key,            // Private key for signing the JWT
        public_key,             // Public key for validating the JWT
        issuer,                 // Issuer of the token
        access_lifetime,        // Access token lifetime
        refresh_lifetime,       // Refresh token lifetime
        token_store,            // Token store (in-memory for this case)
    )
}

// Helper function to generate a JwtTokenGenerator for testing
fn setup_jwt_generator() -> JwtTokenGenerator {
    JwtTokenGenerator::new(
        RSA_PRIVATE_KEY.as_bytes().to_vec(),
        RSA_PUBLIC_KEY.as_bytes().to_vec(),
        "test-issuer".to_string(),
        Duration::from_secs(3600), // Access token valid for 1 hour
        Duration::from_secs(86400), // Refresh token valid for 1 day
        Arc::new(InMemoryTokenStore::new()) // Use in-memory token store for testing
    )
}

    // Test for generating JWT access tokens
    #[test]
    fn test_generate_jwt_access_token() {
        let token_generator = setup_jwt_generator();
        let token = token_generator.generate_access_token("client_id", "user_id", "read:documents").unwrap();
        assert!(!token.is_empty(), "Generated JWT access token should not be empty");
    
        // Decode the token to verify its claims
        let decoding_key = DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY.as_bytes()).unwrap();
        let token_data = decode::<Claims>(&token, &decoding_key, &Validation::new(Algorithm::RS256)).unwrap();
        
        assert_eq!(token_data.claims.sub, "user_id", "Subject should match the user_id");
        assert_eq!(token_data.claims.scope.as_deref(), Some("read:documents"), "Scope should match");
        assert_eq!(token_data.claims.client_id.as_deref(), Some("client_id"), "Client ID should match");
    }
    

    // Test for validating a valid JWT token
    #[test]
    fn test_validate_jwt_token() {
        let jwt_generator = setup_jwt_generator();  // Mock setup
    
        let valid_token = jwt_generator.generate_access_token("client_id", "user_id", "read:documents").unwrap();
    
        // Attempt to validate the token
        let result = jwt_generator.validate_token(
            &valid_token,
            Some("expected_audience"),
            "user_id",
            "read:documents"
        );
    
        // Assert that the result is successful
        assert!(result.is_ok());
    }
    
    
    
    // Test for validating a token with incorrect subject
    #[test]
fn test_validate_expired_jwt_token() {
    let jwt_generator = setup_jwt_generator_with_short_expiry(); // Short expiry (1 second)
    
    // Generate a short-lived token
    let expired_token = jwt_generator.generate_access_token("client_id", "user_id", "read:documents").unwrap();
    
    // Decode token to inspect claims for debugging
    let decoding_key = DecodingKey::from_rsa_pem(&jwt_generator.public_key).unwrap();
    let token_data = decode::<Claims>(&expired_token, &decoding_key, &Validation::new(Algorithm::RS256)).unwrap();
    println!("Token issued at (iat): {}", token_data.claims.iat);
    println!("Token expiration time (exp): {}", token_data.claims.exp);
    
    // Sleep long enough to ensure the token has expired
    std::thread::sleep(std::time::Duration::from_secs(30));  // Ensure token expires
    
    // Attempt to validate the expired token
    let result = jwt_generator.validate_token(
        &expired_token,
        None,  // Skip audience validation for this test
        "user_id",
        "read:documents"
    );
    
    // Assert that the result is an error and the error is ExpiredToken
    assert_eq!(result.unwrap_err(), TokenError::ExpiredToken);
}



    // Test for generating and validating opaque tokens
// Test for generating and validating opaque tokens
#[test]
fn test_generate_opaque_access_token() {
    let opaque_generator = OpaqueTokenGenerator { token_length: 32 }; // Opaque token with 32 chars
    let token = opaque_generator.generate_access_token("client_id", "user_id", "read:documents").unwrap();
    assert_eq!(token.len(), 32, "Generated opaque token should have the correct length");

    // Opaque tokens do not support validation, expect UnsupportedOperation
    let result = opaque_generator.validate_token(&token, None, "user_id", "read:documents");
    assert!(result.is_err(), "Opaque tokens should not support validation");
    assert_eq!(result.unwrap_err(), TokenError::UnsupportedOperation, "Expected UnsupportedOperation error for opaque tokens");
}



    // Test for cleaning up expired tokens
    #[test]
    fn test_cleanup_expired_tokens() -> Result<(), TokenError> {
        let token_store = InMemoryTokenStore::new();
        let token = "expired_token".to_string();
        
        // Add an expired token to the store, mapping the SystemTimeError into TokenError
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| TokenError::InternalError)?;
        let expired_time = current_time.as_secs() - 100; // Set it to an expired timestamp
    
        // Add the expired token to the store but handle the expiration error gracefully
        match token_store.revoke_token(token.clone(), expired_time) {
            Ok(_) => println!("Token revoked successfully"),
            Err(TokenError::ExpiredToken) => println!("Token is already expired, skipping revocation"), // Handle the expired token case
            Err(e) => return Err(e), // Propagate other errors
        }
    
        // Cleanup expired tokens, propagating errors if any
        token_store.cleanup_expired_tokens()?;
    
        // Verify the token is removed, using `?` for error propagation
        let is_revoked = token_store.is_token_revoked(&token)?;
        assert!(!is_revoked, "Expired token should be cleaned up");
    
        Ok(()) // Return success
    }

    #[test]
    fn test_validate_invalid_signature_jwt_token() {
        let jwt_generator = setup_jwt_generator();  // Normal JWT setup
        
        // Generate a valid token
        let valid_token = jwt_generator.generate_access_token("client_id", "user_id", "read:documents").unwrap();
        
        // Manually alter the signature to create an invalid signature
        let parts: Vec<&str> = valid_token.split('.').collect();
        let invalid_token = format!("{}.{}.invalidsignature", parts[0], parts[1]);
        
        // Attempt to validate the token with an invalid signature
        let result = jwt_generator.validate_token(
            &invalid_token,
            Some("expected_audience"),
            "user_id",
            "read:documents"
        );
        
        // Assert that the result is an error and the error is InvalidSignature
        assert_eq!(result.unwrap_err(), TokenError::InvalidSignature);
    }
    
    


}