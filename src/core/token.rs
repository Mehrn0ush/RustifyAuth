use crate::core::authorization::AuthorizationCodeFlow;
use crate::core::types::{TokenError, TokenRequest, TokenResponse};
use crate::jwt::{generate_jwt, get_signing_algorithm};
use crate::security::rate_limit::RateLimiter;
use actix_web::HttpRequest;
use dotenv::dotenv;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use redis::Client;
use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Helper function for getting current time in seconds since UNIX epoch

fn get_current_time() -> Result<u64, TokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| {
            eprintln!("Failed to retrieve current time: {:?}", e);
            TokenError::InternalError
        })
}

pub trait TokenStore: Send + Sync {
    fn store_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
        tbid: Option<String>,
    ) -> Result<(), TokenError>;

    fn revoke_token(&self, token: String, exp: u64) -> Result<(), TokenError>;

    fn validate_refresh_token(
        &self,
        token: &str,
        client_id: &str,
    ) -> Result<(String, u64), TokenError>;

    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError>;

    fn revoke_refresh_token(&self, token: &str) -> Result<(), TokenError>;

    fn cleanup_expired_tokens(&self) -> Result<(), TokenError>;
}

#[derive(Debug, Clone)]
struct TokenUsageLog {
    token: String,
    user_id: String,
    timestamp: u64,
    status: String,
}

pub struct TokenUsageHistory {
    logs: Mutex<Vec<TokenUsageLog>>,
}

impl TokenUsageHistory {
    pub fn new() -> Self {
        TokenUsageHistory {
            logs: Mutex::new(Vec::new()),
        }
    }

    // Method to log token usage
    pub fn log_usage(&self, token: &str, user_id: &str, status: &str) {
        let mut logs = self.logs.lock().unwrap();
        logs.push(TokenUsageLog {
            token: token.to_string(),
            user_id: user_id.to_string(),
            timestamp: get_current_time().unwrap(),
            status: status.to_string(),
        });
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    pub value: String,
    pub expiration: u64,
    pub client_id: String,
    pub user_id: String,
    pub tbid: Option<String>,
}

pub struct RedisTokenStore {
    conn: Arc<Mutex<Connection>>,
}

impl RedisTokenStore {
    pub fn new(client: &Client) -> Result<Self, TokenError> {
        let conn = client
            .get_connection()
            .map_err(|_| TokenError::InternalError)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl TokenStore for RedisTokenStore {
    fn store_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
        tbid: Option<String>,
    ) -> Result<(), TokenError> {
        // Assume tbid is handled separately or included in the token value *****************
        //   let tbid = get_tbid_from_current_context()?; // We should Implement this function based on context ***

        let token_data = Token {
            value: token.to_string(),
            expiration: exp,
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            tbid,
        };

        let serialized =
            serde_json::to_string(&token_data).map_err(|_| TokenError::InternalError)?;

        let current_time = get_current_time()?;
        if exp <= current_time {
            // Token has already expired; do not store it
            println!("Token {} has already expired; not storing in Redis.", token);
            return Ok(());
        }
        let ttl = exp - current_time;

        let mut conn = self.conn.lock().map_err(|_| TokenError::InternalError)?;
        redis::cmd("SETEX")
            .arg(token)
            .arg(ttl as usize)
            .arg(exp)
            .query::<()>(&mut *conn)
            .map_err(|e| {
                println!("Failed to store refresh token: {:?}", e);
                TokenError::InternalError
            })?;
        Ok(())
    }

    fn validate_refresh_token(
        &self,
        token: &str,
        client_id: &str,
    ) -> Result<(String, u64), TokenError> {
        let mut conn = self.conn.lock().map_err(|_| TokenError::InternalError)?;
        let key = format!("refresh_token:{}", token);
        let result: Option<String> = conn.get(&key).map_err(|_| TokenError::InternalError)?;
        if let Some(value) = result {
            let token_data: Token =
                serde_json::from_str(&value).map_err(|_| TokenError::InvalidToken)?;
            if token_data.client_id == client_id {
                let (stored_client_id, user_id): (String, String) =
                    serde_json::from_str(&value).map_err(|_| TokenError::InvalidToken)?;
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
        } else {
            Err(TokenError::InvalidToken)
        }
    }

    fn revoke_token(&self, token: String, exp: u64) -> Result<(), TokenError> {
        let now = get_current_time()?;

        if is_token_expired(exp, now) {
            println!("Token {} has already expired, skipping revocation.", token);
            return Ok(()); // Token is expired, so no need to revoke
        }

        let ttl = calculate_ttl(exp, now);
        self.store_revoked_token(token, ttl)
    }

    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError> {
        let mut conn = self.conn.lock().map_err(|_| TokenError::InternalError)?;
        let result: Option<String> = conn.get(token).map_err(|_| TokenError::InternalError)?;

        // If token is not found (expired), consider it revoked
        Ok(result.is_none() || result.as_deref() == Some("revoked"))
    }

    fn revoke_refresh_token(&self, token: &str) -> Result<(), TokenError> {
        let mut conn = self.conn.lock().map_err(|_| TokenError::InternalError)?;
        let result: Option<String> = conn.get(token).map_err(|_| TokenError::InternalError)?;

        if result.is_some() {
            conn.del(token).map_err(|_| TokenError::InternalError)?;
            println!("Revoked refresh token in Redis: {}", token);
            Ok(())
        } else {
            println!("Refresh token not found in Redis: {}", token);
            Err(TokenError::InvalidToken)
        }
    }
    fn cleanup_expired_tokens(&self) -> Result<(), TokenError> {
        println!("Redis automatically cleans up expired tokens.");
        Ok(()) // Redis handles this automatically with TTL
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
}

/*
    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError> {
        // Handle possible errors when locking the connection and retrieving the token status.
        let mut conn = self.conn.lock().map_err(|_| TokenError::InternalError)?; // Lock the connection
        let result: Option<String> = conn.get(token).map_err(|_| TokenError::InternalError)?; // Get token status
        Ok(result.as_deref() == Some("revoked")) // Return true if the token is revoked
    }
    #[allow(dead_code)]
    fn cleanup_expired_tokens(&self) -> Result<(), TokenError> {
        // Redis automatically handles expired keys, so no manual cleanup is needed.
        println!("Redis automatically cleans up expired tokens.");
        Ok(())
    }
}

    */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenData {
    pub token: String,
    pub client_id: String,
    pub user_id: String,
    pub expiration: u64,
}

#[derive(Debug)]
pub struct InMemoryTokenStore {
    revoked_tokens: Mutex<HashMap<String, u64>>, // Token -> Expiration timestamp
    refresh_tokens: Arc<Mutex<HashMap<String, RefreshTokenData>>>,
    active_tokens: Mutex<HashMap<String, Token>>,
}

impl InMemoryTokenStore {
    // Constructor method for InMemoryTokenStore
    pub fn new() -> Self {
        Self {
            revoked_tokens: Mutex::new(HashMap::new()),
            active_tokens: Mutex::new(HashMap::new()),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(dead_code)]
    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError> {
        let revoked_tokens = self.get_revoked_tokens()?;
        if let Some(&exp) = revoked_tokens.get(token) {
            if get_current_time()? <= exp {
                return Ok(true); // Token is revoked but not expired
            }
        }
        Ok(false) // Token is not revoked or has already expired
    }

    // Helper function to lock and get the revoked tokens map
    fn get_revoked_tokens(&self) -> Result<MutexGuard<'_, HashMap<String, u64>>, TokenError> {
        self.revoked_tokens.lock().map_err(|e| {
            eprintln!("Failed to acquire lock on revoked_tokens: {:?}", e);
            TokenError::InternalError
        })
    }

    // Helper function to lock and get the active tokens map
    fn get_active_tokens(&self) -> Result<MutexGuard<'_, HashMap<String, Token>>, TokenError> {
        self.active_tokens.lock().map_err(|e| {
            eprintln!("Failed to acquire lock on active_tokens: {:?}", e);
            TokenError::InternalError
        })
    }

    fn store_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
        tbid: Option<String>,
    ) -> Result<(), TokenError> {
        let mut refresh_tokens = self.refresh_tokens.lock().unwrap();
        refresh_tokens.insert(
            token.to_string(),
            RefreshTokenData {
                token: token.to_string(),
                client_id: client_id.to_string(),
                user_id: user_id.to_string(),
                expiration: exp,
            },
        );
        Ok(())
    }

    pub fn store_access_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        expiration: u64,
    ) -> Result<(), TokenError> {
        let mut active_tokens = self.active_tokens.lock().unwrap();
        active_tokens.insert(
            token.to_string(),
            Token {
                value: token.to_string(),
                expiration,
                client_id: client_id.to_string(),
                user_id: user_id.to_string(),
                tbid: None, // You can modify this if tbid is available
            },
        );
        Ok(()) // Fix: Return the appropriate Result type
    }

    fn validate_refresh_token(
        &self,
        token: &str,
        client_id: &str,
    ) -> Result<(String, u64), TokenError> {
        let refresh_tokens = self.refresh_tokens.lock().unwrap();
        if let Some(token_data) = refresh_tokens.get(token) {
            if token_data.expiration > get_current_time()? {
                if token_data.client_id == client_id {
                    return Ok((token_data.user_id.clone(), token_data.expiration));
                } else {
                    return Err(TokenError::InvalidClient);
                }
            } else {
                return Err(TokenError::ExpiredToken);
            }
        }
        Err(TokenError::InvalidToken)
    }

    fn revoke_refresh_token(&self, token: &str) -> Result<(), TokenError> {
        let mut refresh_tokens = self.refresh_tokens.lock().unwrap();
        if refresh_tokens.remove(token).is_some() {
            Ok(())
        } else {
            Err(TokenError::InvalidToken)
        }
    }
    fn cleanup_expired_tokens(&self) -> Result<(), TokenError> {
        let current_time = get_current_time()?;
        let mut active_tokens = self.get_active_tokens()?;
        let mut revoked_tokens = self.get_revoked_tokens()?;

        active_tokens.retain(|_, token| {
            if token.expiration > current_time {
                true // Keep valid tokens
            } else {
                println!("Removing expired token: {}", token.value);
                revoked_tokens.insert(token.value.clone(), token.expiration); // Move expired token to revoked
                false // Remove expired tokens from active_tokens
            }
        });

        Ok(())
    }
}

/*
fn get_current_time() -> Result<u64, TokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| {
            eprintln!("Failed to retrieve current time: {:?}", e);
            TokenError::InternalError
        })
} */

// Helper function to check if the token is expired
fn is_token_expired(exp: u64, now: u64) -> bool {
    exp <= now
}

impl TokenStore for InMemoryTokenStore {
    fn store_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
        tbid: Option<String>,
    ) -> Result<(), TokenError> {
        let mut refresh_tokens = self.refresh_tokens.lock().unwrap();
        refresh_tokens.insert(
            token.to_string(),
            RefreshTokenData {
                token: token.to_string(),
                client_id: client_id.to_string(),
                user_id: user_id.to_string(),
                expiration: exp,
            },
        );
        Ok(())
    }

    fn validate_refresh_token(
        &self,
        token: &str,
        client_id: &str,
    ) -> Result<(String, u64), TokenError> {
        let refresh_tokens = self.refresh_tokens.lock().unwrap();
        if let Some(token_data) = refresh_tokens.get(token) {
            if token_data.expiration > get_current_time()? {
                if token_data.client_id == client_id {
                    return Ok((token_data.user_id.clone(), token_data.expiration));
                } else {
                    return Err(TokenError::InvalidClient);
                }
            } else {
                return Err(TokenError::ExpiredToken);
            }
        }
        Err(TokenError::InvalidToken)
    }

    fn revoke_token(&self, token: String, exp: u64) -> Result<(), TokenError> {
        let now = get_current_time()?;

        if is_token_expired(exp, now) {
            println!("Token {} has already expired.", token);
            return Err(TokenError::ExpiredToken); // Log expired tokens and return an error
        }

        let mut revoked_tokens = self.get_revoked_tokens()?;
        revoked_tokens.insert(token.clone(), exp);
        println!("Revoked token: {}, exp: {}", token, exp);
        Ok(())
    }

    fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError> {
        let revoked_tokens = self.get_revoked_tokens()?;

        if let Some(&exp) = revoked_tokens.get(token) {
            let current_time = get_current_time()?;
            if current_time <= exp {
                // Token is revoked but not expired
                return Ok(true);
            }
        }
        // Token is not revoked or already expired
        Ok(false)
    }
    fn revoke_refresh_token(&self, token: &str) -> Result<(), TokenError> {
        let mut refresh_tokens = self.refresh_tokens.lock().unwrap();
        if refresh_tokens.remove(token).is_some() {
            Ok(())
        } else {
            Err(TokenError::InvalidToken)
        }
    }

    fn cleanup_expired_tokens(&self) -> Result<(), TokenError> {
        self.cleanup_expired_tokens()
    }
}

// Helper function for getting token
#[allow(dead_code)]
fn get_token_config() -> (Option<String>, String, String) {
    dotenv().ok(); // Load the .env file

    let audience = env::var("TOKEN_AUDIENCE").ok(); // Option<String>

    let subject = env::var("TOKEN_SUBJECT").unwrap_or_else(|_| "default_subject".to_string()); // Default value for subject

    let required_scope = env::var("TOKEN_SCOPE").unwrap_or_else(|_| "default_scope".to_string()); // Default value for scope

    (audience, subject, required_scope)
}

// TokenGenerator trait defines a contract for generating access and refresh tokens
pub trait TokenGenerator: Send + Sync {
    fn access_token_lifetime(&self) -> Duration;
    fn generate_access_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<String, TokenError>;
    fn generate_refresh_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<String, TokenError>;
    fn validate_token(
        &self,
        token: &str,
        expected_aud: Option<&str>,
        expected_sub: &str,
        required_scope: &str,
        tbid: Option<String>,
    ) -> Result<TokenData<Claims>, TokenError>; // Leave as a trait method signature

    fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<(String, String), TokenError>;
}

// JWT token generator using RS256
pub struct JwtTokenGenerator {
    pub private_key: Vec<u8>,             // RS256 private key for JWT
    pub public_key: Vec<u8>,              // RS256 public key for JWT validation
    pub issuer: String,                   // Token issuer (for claim)
    pub access_token_lifetime: Duration,  // Access token validity duration
    pub refresh_token_lifetime: Duration, // Refresh token validity duration
    pub token_store: Arc<dyn TokenStore>,
}

impl JwtTokenGenerator {
    // Constructor for JwtTokenGenerator
    pub fn new(
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        issuer: String,
        access_token_lifetime: Duration,
        refresh_token_lifetime: Duration,
        token_store: Arc<dyn TokenStore>,
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

    pub fn generate_access_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<String, TokenError> {
        self.generate_access_token_internal(client_id, user_id, scope, tbid)
    }

    pub fn generate_refresh_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<String, TokenError> {
        self.generate_refresh_token_internal(client_id, user_id, scope, tbid)
    }

    // Exchange refresh token and rotate refresh token as per OAuth 2.0 security best practices
    pub fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<(String, String), TokenError> {
        // Step 1: Validate the refresh token and get the user_id and expiration time
        let (user_id, exp) = self
            .token_store
            .validate_refresh_token(refresh_token, client_id)?;

        // Step 2: Revoke the old refresh token using the expiration time
        self.token_store
            .revoke_token(refresh_token.to_string(), exp)?;

        // Step 3: Generate a new access token
        let access_token =
            self.generate_access_token_internal(client_id, &user_id, scope, tbid.clone())?;

        // Step 4: Generate a new refresh token
        let new_refresh_token =
            self.generate_refresh_token_internal(client_id, &user_id, scope, tbid.clone())?;

        // Step 5: Store the new refresh token with the updated expiration time
        let new_exp = get_current_time()? + self.refresh_token_lifetime.as_secs();
        self.token_store.store_refresh_token(
            &new_refresh_token,
            client_id,
            &user_id,
            new_exp,
            tbid,
        )?;

        Ok((access_token, new_refresh_token))
    }

    // Helper function to sign JWT tokens
    pub fn sign_token(&self, claims: &Claims) -> Result<String, TokenError> {
        let header = Header::new(Algorithm::RS256);
        println!("Signing JWT token with RS256 algorithm.");

        let encoding_key = EncodingKey::from_rsa_pem(&self.private_key).map_err(|e| {
            println!("Error loading private key for signing: {:?}", e);
            TokenError::InternalError
        })?;

        encode(&header, claims, &encoding_key).map_err(|e| {
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
    fn create_claims(
        &self,
        client_id: &str,
        user_id: &str,
        expiration: Duration,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<Claims, TokenError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
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
            tbid,
        })
    }

    // Generate an access token internally
    pub fn generate_access_token_internal(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<String, TokenError> {
        let claims =
            self.create_claims(client_id, user_id, self.access_token_lifetime, scope, tbid)?;

        let token = self.sign_token(&claims)?;

        Ok(token)
    }

    // Generate a refresh token internally
    pub fn generate_refresh_token_internal(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<String, TokenError> {
        let claims =
            self.create_claims(client_id, user_id, self.refresh_token_lifetime, scope, tbid)?;
        self.sign_token(&claims)
    }

    // Validate JWT claims for access token
    pub fn validate_token(
        &self,
        token: &str,
        _expected_aud: Option<&str>,
        expected_sub: &str,
        required_scope: &str,
        tbid: Option<String>,
    ) -> Result<TokenData<Claims>, TokenError> {
        println!("Validating token: {}", token);

        // Decode the token and check for expiration
        let decoding_key = DecodingKey::from_rsa_pem(&self.public_key).map_err(|e| {
            println!("Error loading public key for validation: {:?}", e);
            TokenError::InternalError
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
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
            println!(
                "Token subject mismatch: expected {}, got {}",
                expected_sub, token_data.claims.sub
            );
            return Err(TokenError::InvalidGrant);
        }

        // Validate TBID
        if let Some(tbid_expected) = tbid {
            if let Some(tbid_token) = &token_data.claims.tbid {
                if tbid_expected != *tbid_token {
                    println!(
                        "Token Binding ID mismatch: expected {}, got {}",
                        tbid_expected, tbid_token
                    );
                    return Err(TokenError::InvalidGrant);
                }
            } else {
                println!("Token Binding ID is missing in token claims.");
                return Err(TokenError::InvalidGrant);
            }
        } else {
            println!("No Token Binding ID provided for validation.");
            return Err(TokenError::InvalidGrant);
        }

        println!("Token {} successfully validated.", token);
        Ok(token_data)
    }

    // Revoke a JWT access token
    fn revoke_jwt_access_token(&self, token: &str) -> Result<(), TokenError> {
        let exp = self.get_token_exp(token)?; // Get token expiration time
                                              // Revoke the JWT access token
        self.token_store.revoke_token(token.to_string(), exp)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TokenError::InternalError)?
            .as_secs();

        println!("Current time (now): {}", now);

        if exp <= now {
            println!("Token has already expired.");
            return Err(TokenError::ExpiredToken);
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
            return Err(TokenError::ExpiredToken); // Return an error indicating the token is already expired
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
        tbid: Option<String>,
    ) -> Result<(String, String), TokenError> {
        // Step 1: Validate the refresh token
        let (user_id, exp) = self
            .token_store
            .validate_refresh_token(refresh_token, client_id)?;

        // Step 2: Revoke the old refresh token
        self.token_store.revoke_token(
            refresh_token.to_string(),
            self.refresh_token_lifetime.as_secs(),
        )?;

        // Step 3: Generate a new access token
        let access_token = self.generate_access_token(client_id, &user_id, scope, tbid.clone())?;

        // Step 4: Generate a new refresh token
        let new_refresh_token =
            self.generate_refresh_token(client_id, &user_id, scope, tbid.clone())?;

        // Step 5: Store the new refresh token
        let new_exp = get_current_time()? + self.refresh_token_lifetime.as_secs();
        self.token_store.store_refresh_token(
            &new_refresh_token,
            client_id,
            &user_id,
            new_exp,
            tbid,
        )?;

        Ok((access_token, new_refresh_token))
    }

    fn access_token_lifetime(&self) -> Duration {
        self.access_token_lifetime
    }

    fn generate_access_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<String, TokenError> {
        self.generate_access_token_internal(client_id, user_id, scope, tbid)
    }

    fn generate_refresh_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        tbid: Option<String>,
    ) -> Result<String, TokenError> {
        self.generate_refresh_token_internal(client_id, user_id, scope, tbid)
    }

    fn validate_token(
        &self,
        token: &str,
        _expected_aud: Option<&str>,
        expected_sub: &str,
        required_scope: &str,
        tbid: Option<String>,
    ) -> Result<TokenData<Claims>, TokenError> {
        self.validate_token(token, _expected_aud, expected_sub, required_scope, tbid)
    }
}

/*
        // Step 1: Decode the token to check expiration and validity
        let decoding_key = DecodingKey::from_rsa_pem(&self.public_key).map_err(|e| {
            println!("Error loading public key for validation: {:?}", e);
            TokenError::InternalError
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true; // Ensure expiration is checked
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
            .as_ref() // Borrow the value instead of moving it
            .map(|scope| scope.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_else(HashSet::new); // Handle `None` safely by providing an empty set

        if !token_scopes.contains(required_scope) {
            println!("Token is missing the required scope: {}", required_scope);
            return Err(TokenError::InsufficientScope);
        }

        // Step 4: Check subject
        if token_data.claims.sub != expected_sub {
            println!(
                "Token subject mismatch: expected {}, got {}",
                expected_sub, token_data.claims.sub
            );
            return Err(TokenError::InvalidGrant);
        }


        // Validate TBID
        if let Some(tbid_expected) = tbid {
            if let Some(tbid_token) = &token_data.claims.tbid {
                if tbid_expected != *tbid_token {
                    println!("Token Binding ID mismatch: expected {}, got {}", tbid_expected, tbid_token);
                    return Err(TokenError::InvalidGrant);
                }
            } else {
                println!("Token Binding ID is missing in token claims.");
                return Err(TokenError::InvalidGrant);
            }
        } else {
            println!("No Token Binding ID provided for validation.");
            return Err(TokenError::InvalidGrant);
        }

        println!("Token {} successfully validated.", token);
        Ok(token_data)
    }
}*/

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub scope: Option<String>,
    pub aud: Option<String>,
    pub client_id: Option<String>,
    pub iat: u64,
    pub iss: Option<String>,
    pub tbid: Option<String>,
}

// Opaque token generator using random strings
pub struct OpaqueTokenGenerator {
    token_length: usize, // Length of the random token
}

impl OpaqueTokenGenerator {
    // Helper function to generate a random opaque token
    fn generate_random_token(&self) -> String {
        // Ensure the randomness is sufficient by checking token length
        assert!(self.token_length > 0, "Token length must be greater than 0"); // *********

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
        Duration::from_secs(3600) // 1 hour
    }

    // Handle refresh token exchange for opaque tokens
    fn exchange_refresh_token(
        &self,
        _refresh_token: &str,
        _client_id: &str,
        _scope: &str,
        _tbid: Option<String>,
    ) -> Result<(String, String), TokenError> {
        // In this case, we may not need to handle refresh tokens for opaque tokens,
        // but here is a placeholder to comply with the trait.

        // Normally, we would validate the refresh token, but opaque tokens may not support it.
        println!("Opaque tokens do not support refresh token exchange.");
        Err(TokenError::UnsupportedOperation) // Returning an error because it's not supported.
    }

    fn validate_token(
        &self,
        _token: &str,
        _expected_aud: Option<&str>,
        _expected_sub: &str,
        _required_scope: &str,
        _tbid: Option<String>,
    ) -> Result<TokenData<Claims>, TokenError> {
        // Opaque tokens do not carry claims or support validation like JWT tokens.
        // Hence, this operation is not supported for opaque tokens.
        println!("Opaque tokens do not support validation.");
        Err(TokenError::UnsupportedOperation)
    }

    fn generate_access_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
        _tbid: Option<String>,
    ) -> Result<String, TokenError> {
        println!("Generating opaque access token.");
        self.generate_access_token_internal()
    }

    fn generate_refresh_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
        _tbid: Option<String>,
    ) -> Result<String, TokenError> {
        println!("Generating opaque refresh token.");
        self.generate_refresh_token_internal()
    }
}

pub fn extract_tbid(req: &HttpRequest) -> Result<String, TokenError> {
    if let Some(tbid_header) = req.headers().get("X-Token-Binding") {
        if let Ok(tbid_str) = tbid_header.to_str() {
            Ok(tbid_str.to_string())
        } else {
            Err(TokenError::InvalidTokenBinding)
        }
    } else {
        Err(TokenError::MissingTokenBinding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::token::{JwtTokenGenerator, TokenError, TokenStore};
    use crate::endpoints::register::{ClientMetadata, ClientRegistrationResponse, ClientStore};
    use crate::jwt::sign_with_rsa;
    use actix_web::{test, web, App};
    use actix_web_httpauth::extractors::bearer::BearerAuth;
    use env_logger;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::env;
    use std::sync::RwLock;
    use std::sync::{Arc, Mutex};
    use std::thread::sleep;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let access_lifetime = Duration::from_secs(1); // 1 second expiration
        let refresh_lifetime = Duration::from_secs(2); // 2 seconds expiration

        let token_store = Arc::new(InMemoryTokenStore::new());

        // Call the `new` function with the correct number of arguments
        JwtTokenGenerator::new(
            private_key,      // Private key for signing the JWT
            public_key,       // Public key for validating the JWT
            issuer,           // Issuer of the token
            access_lifetime,  // Access token lifetime
            refresh_lifetime, // Refresh token lifetime
            token_store,      // Token store (in-memory for this case)
        )
    }

    // Helper function to generate a JwtTokenGenerator for testing
    fn setup_jwt_generator() -> JwtTokenGenerator {
        JwtTokenGenerator::new(
            RSA_PRIVATE_KEY.as_bytes().to_vec(),
            RSA_PUBLIC_KEY.as_bytes().to_vec(),
            "test-issuer".to_string(),
            Duration::from_secs(3600),  // Access token valid for 1 hour
            Duration::from_secs(86400), // Refresh token valid for 1 day
            Arc::new(InMemoryTokenStore::new()), // Use in-memory token store for testing
        )
    }

    // Mock TokenStore for testing
    struct MockTokenStore {
        tokens: Mutex<HashMap<String, u64>>, // Mock store to simulate token expiry
    }

    impl MockTokenStore {
        pub fn new() -> Self {
            MockTokenStore {
                tokens: Mutex::new(HashMap::new()),
            }
        }
    }

    impl TokenStore for MockTokenStore {
        fn store_refresh_token(
            &self,
            token: &str,
            client_id: &str,
            user_id: &str,
            exp: u64,
            tbid: Option<String>,
        ) -> Result<(), TokenError> {
            let mut tokens = self.tokens.lock().unwrap();
            tokens.insert(token.to_string(), exp);

            Ok(())
        }

        fn revoke_token(&self, token: String, _exp: u64) -> Result<(), TokenError> {
            let mut tokens = self.tokens.lock().unwrap();
            tokens.remove(&token);
            Ok(())
        }

        fn validate_refresh_token(
            &self,
            token: &str,
            _client_id: &str,
        ) -> Result<(String, u64), TokenError> {
            let tokens = self.tokens.lock().unwrap();
            if let Some(token_data) = tokens.get(token) {
                if *token_data > get_current_time()? {
                    return Ok((token_data.to_string(), *token_data));
                } else {
                    return Err(TokenError::ExpiredToken);
                }
            }
            Err(TokenError::InvalidGrant)
        }

        fn is_token_revoked(&self, token: &str) -> Result<bool, TokenError> {
            let tokens = self.tokens.lock().unwrap();
            let contains = tokens.contains_key(token);
            println!(
                "is_token_revoked: token '{}', contains: {}",
                token, contains
            );
            Ok(!contains) // Token is revoked if it's not in the store
        }

        fn revoke_refresh_token(&self, token: &str) -> Result<(), TokenError> {
            let mut tokens = self.tokens.lock().unwrap();
            if tokens.remove(token).is_some() {
                Ok(())
            } else {
                Err(TokenError::InvalidToken)
            }
        }

        fn cleanup_expired_tokens(&self) -> Result<(), TokenError> {
            let current_time = get_current_time()?; // Get the current time in seconds
            let mut expired_tokens = Vec::new(); // Collect expired tokens to remove later

            // Lock the token store for thread safety
            let mut tokens = self.tokens.lock().map_err(|_| TokenError::InternalError)?;

            // Iterate over the tokens in the store
            for (token, token_data) in tokens.iter() {
                println!(
                    "Checking token: {}, Exp: {}, Now: {}",
                    token, token_data, current_time
                );
                if *token_data <= current_time {
                    // Compare expiration with current time
                    // Token has expired, so mark it for removal
                    expired_tokens.push(token.clone());
                }
            }

            // Now, remove all expired tokens and mark them as revoked
            for token in expired_tokens {
                tokens.remove(&token); // Remove expired token from active store
                println!("Removing expired token: {}", token);
            }

            Ok(())
        }
    }

    // Mock implementation of get_tbid_from_current_context
    fn get_tbid_from_current_context() -> Result<String, TokenError> {
        Ok("mock_tbid".to_string())
    }

    // Helper function to get current time
    fn get_current_time() -> Result<u64, TokenError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| TokenError::InternalError)
    }

    // Define the register_client_handler for testing
    async fn register_client_handler(
        req: web::Json<ClientMetadata>,
    ) -> web::Json<ClientRegistrationResponse> {
        // Mock implementation for testing
        web::Json(ClientRegistrationResponse {
            client_id: "mock_client_id".to_string(),
            client_secret: "mock_client_secret".to_string(),
        })
    }

    #[test]
    async fn test_exchange_refresh_token_success() -> Result<(), TokenError> {
        let private_key = RSA_PRIVATE_KEY.as_bytes().to_vec();
        let public_key = RSA_PUBLIC_KEY.as_bytes().to_vec();
        let token_store = Arc::new(MockTokenStore::new());

        let generator = JwtTokenGenerator::new(
            private_key,
            public_key,
            "issuer".to_string(),
            Duration::from_secs(3600),
            Duration::from_secs(7200),
            token_store.clone(),
        );

        // Mock refresh token creation
        let refresh_token = "mock_refresh_token";
        let client_id = "client_id";
        let user_id = "user_id";
        let scope = "read write";
        let tbid = Some("test_tbid".to_string());

        // Store refresh token with valid expiration
        let exp = get_current_time()? + 7200; // Set expiration for the refresh token
        token_store.store_refresh_token(refresh_token, client_id, user_id, exp, tbid.clone())?;

        println!("Stored refresh token: {}, exp: {}", refresh_token, exp);

        // Act: Exchange the refresh token for new tokens
        let result =
            generator.exchange_refresh_token(refresh_token, client_id, scope, tbid.clone());

        assert!(result.is_ok(), "Failed to exchange refresh token");
        let (access_token, new_refresh_token) = result.unwrap();

        println!("Generated access token: {}", access_token);
        println!("Generated new refresh token: {}", new_refresh_token);

        assert!(!access_token.is_empty(), "Access token should not be empty");
        assert!(
            !new_refresh_token.is_empty(),
            "New refresh token should not be empty"
        );

        // Optionally, validate the new tokens
        let decoded_access = decode::<Claims>(
            &access_token,
            &DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY.as_bytes()).unwrap(),
            &Validation::new(Algorithm::RS256),
        )
        .unwrap();

        assert_eq!(
            decoded_access.claims.tbid.unwrap(),
            tbid.unwrap(),
            "TBID should match"
        );

        Ok(())
    }

    #[test]
    async fn test_exchange_refresh_token_with_invalid_token() {
        let private_key = vec![];
        let public_key = vec![];
        let token_store = Arc::new(MockTokenStore::new());

        let generator = JwtTokenGenerator::new(
            private_key,
            public_key,
            "issuer".to_string(),
            Duration::from_secs(3600),
            Duration::from_secs(7200),
            token_store.clone(),
        );

        // Act: Try exchanging an invalid refresh token
        let result =
            generator.exchange_refresh_token("invalid_refresh_token", "client_id", "read", None);

        // Assert
        assert!(result.is_err(), "Invalid refresh token should fail");
        assert_eq!(
            result.unwrap_err(),
            TokenError::InvalidGrant,
            "Expected InvalidGrant error"
        );
    }

    #[test]
    async fn test_revoke_expired_token() {
        let private_key = vec![];
        let public_key = vec![];
        let token_store = Arc::new(MockTokenStore::new());

        let generator = JwtTokenGenerator::new(
            private_key,
            public_key,
            "issuer".to_string(),
            Duration::from_secs(3600),
            Duration::from_secs(7200),
            token_store.clone(),
        );

        // Mock expired refresh token
        let expired_token = "expired_token";
        let client_id = "client_id";
        let exp = get_current_time().unwrap() - 100; // Set expired timestamp
        token_store
            .store_refresh_token(expired_token, client_id, "user_id", exp, None)
            .unwrap();

        // Act: Attempt to exchange the expired refresh token
        let result = generator.exchange_refresh_token(expired_token, client_id, "read", None);

        // Assert
        assert!(result.is_err(), "Exchange with expired token should fail");
        assert_eq!(
            result.unwrap_err(),
            TokenError::ExpiredToken,
            "Expected InvalidGrant error for expired token"
        );
    }

    #[test]
    async fn test_cleanup_expired_tokens() -> Result<(), TokenError> {
        let private_key = vec![];
        let public_key = vec![];
        let token_store = Arc::new(MockTokenStore::new());

        let generator = JwtTokenGenerator::new(
            private_key,
            public_key,
            "issuer".to_string(),
            Duration::from_secs(3600), // Access token lifetime (1 hour)
            Duration::from_secs(7200), // Refresh token lifetime (2 hours)
            token_store.clone(),
        );

        let expired_token = "expired_token";
        let valid_token = "valid_token";
        let client_id = "client_id";
        let user_id = "user_id";

        // Get the current time in seconds since UNIX epoch
        let current_time = get_current_time()?;

        // Store an expired token (expired 100 seconds ago)
        token_store.store_refresh_token(
            expired_token,
            client_id,
            user_id,
            current_time - 100,
            None,
        )?;

        // Store a valid token that expires in 2 hours (7200 seconds from now)
        token_store.store_refresh_token(
            valid_token,
            client_id,
            user_id,
            current_time + 7200,
            None,
        )?;

        println!("Before cleanup:");
        println!(
            "Expired token exists: {}",
            token_store.is_token_revoked(expired_token)?
        );
        println!(
            "Valid token exists: {}",
            token_store.is_token_revoked(valid_token)?
        );

        // Perform the cleanup
        token_store.cleanup_expired_tokens()?;

        // After cleanup, the expired token should be revoked, and the valid token should not be revoked
        assert!(
            token_store.is_token_revoked(expired_token)?,
            "Expired token should be revoked"
        );
        assert!(
            !token_store.is_token_revoked(valid_token)?,
            "Valid token should not be revoked"
        );

        println!("After cleanup:");
        println!(
            "Expired token exists: {}",
            token_store.is_token_revoked(expired_token)?
        );
        println!(
            "Valid token exists: {}",
            token_store.is_token_revoked(valid_token)?
        );

        Ok(())
    }

    // Test for generating JWT access tokens
    #[test]
    async fn test_generate_jwt_access_token() {
        let token_generator = setup_jwt_generator();
        let tbid = Some("test_tbid".to_string());
        let token = token_generator
            .generate_access_token("client_id", "user_id", "read:documents", tbid.clone())
            .unwrap();
        assert!(
            !token.is_empty(),
            "Generated JWT access token should not be empty"
        );

        // Decode the token to verify its claims
        let decoding_key = DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY.as_bytes()).unwrap();
        let token_data =
            decode::<Claims>(&token, &decoding_key, &Validation::new(Algorithm::RS256)).unwrap();

        assert_eq!(
            token_data.claims.sub, "user_id",
            "Subject should match the user_id"
        );
        assert_eq!(
            token_data.claims.scope.as_deref(),
            Some("read:documents"),
            "Scope should match"
        );
        assert_eq!(
            token_data.claims.client_id.as_deref(),
            Some("client_id"),
            "Client ID should match"
        );
        assert_eq!(
            token_data.claims.tbid.unwrap(),
            tbid.unwrap(),
            "TBID should match"
        );
    }

    // Test for validating a valid JWT token
    #[test]
    async fn test_validate_jwt_token() -> Result<(), TokenError> {
        let private_key = RSA_PRIVATE_KEY.as_bytes().to_vec(); // Load your RSA private key
        let public_key = RSA_PUBLIC_KEY.as_bytes().to_vec(); // Load your RSA public key

        // Create a token store (in-memory for the purpose of the test)
        let token_store = Arc::new(InMemoryTokenStore::new());

        // Create the JWT token generator with the private and public keys
        let jwt_generator = JwtTokenGenerator::new(
            private_key,
            public_key,
            "issuer".to_string(),      // Issuer of the token
            Duration::from_secs(3600), // Access token lifetime
            Duration::from_secs(7200), // Refresh token lifetime
            token_store.clone(),
        );

        // Generate a valid access token with TBID
        let tbid = Some("test_tbid".to_string());
        let valid_token = jwt_generator
            .generate_access_token("client_id", "user_id", "read:documents", tbid.clone())
            .unwrap();

        // Ensure the token is not revoked before validation
        assert!(
            !token_store.is_token_revoked(&valid_token)?,
            "Newly generated token should not be revoked."
        );

        // Validate the token (no audience, but check subject, scope, and tbid)
        let result = jwt_generator.validate_token(
            &valid_token,
            None,             // No audience expected, so we pass None
            "user_id",        // Expected subject (user_id in the token)
            "read:documents", // Required scope (matching what was generated)
            tbid.clone(),     // Provide the expected tbid
        );

        // Assert that the token validation succeeded
        assert!(
            result.is_ok(),
            "JWT validation should succeed for a valid token."
        );

        // Optionally, inspect the token data
        let token_data = result.unwrap();
        assert_eq!(token_data.claims.tbid.unwrap(), tbid.unwrap());

        Ok(())
    }

    // Test for validating a token with incorrect subject or tbid
    #[test]
    async fn test_validate_jwt_token_with_incorrect_tbid() -> Result<(), TokenError> {
        let private_key = RSA_PRIVATE_KEY.as_bytes().to_vec(); // Load your RSA private key
        let public_key = RSA_PUBLIC_KEY.as_bytes().to_vec(); // Load your RSA public key

        // Create a token store (in-memory for the purpose of the test)
        let token_store = Arc::new(InMemoryTokenStore::new());

        // Create the JWT token generator with the private and public keys
        let jwt_generator = JwtTokenGenerator::new(
            private_key,
            public_key,
            "issuer".to_string(),      // Issuer of the token
            Duration::from_secs(3600), // Access token lifetime
            Duration::from_secs(7200), // Refresh token lifetime
            token_store.clone(),
        );

        // Generate a valid access token with TBID
        let tbid = Some("test_tbid".to_string());
        let valid_token = jwt_generator
            .generate_access_token("client_id", "user_id", "read:documents", tbid.clone())
            .unwrap();

        // Attempt to validate the token with an incorrect TBID
        let incorrect_tbid = Some("wrong_tbid".to_string());
        let result = jwt_generator.validate_token(
            &valid_token,
            None,             // No audience expected, so we pass None
            "user_id",        // Expected subject (user_id in the token)
            "read:documents", // Required scope (matching what was generated)
            incorrect_tbid,   // Provide an incorrect tbid
        );

        // Assert that the validation fails due to TBID mismatch
        assert!(
            result.is_err(),
            "Validation should fail due to TBID mismatch"
        );
        assert_eq!(
            result.unwrap_err(),
            TokenError::InvalidGrant,
            "Expected InvalidGrant error for TBID mismatch"
        );

        Ok(())
    }

    // Test for generating and validating opaque tokens
    #[test]
    async fn test_generate_opaque_access_token() {
        let opaque_generator = OpaqueTokenGenerator { token_length: 32 }; // Opaque token with 32 chars
        let token = opaque_generator
            .generate_access_token("client_id", "user_id", "read:documents", None)
            .unwrap();
        assert_eq!(
            token.len(),
            32,
            "Generated opaque token should have the correct length"
        );

        // Opaque tokens do not support validation, expect UnsupportedOperation
        let result =
            opaque_generator.validate_token(&token, None, "user_id", "read:documents", None);
        assert!(
            result.is_err(),
            "Opaque tokens should not support validation"
        );
        assert_eq!(
            result.unwrap_err(),
            TokenError::UnsupportedOperation,
            "Expected UnsupportedOperation error for opaque tokens"
        );
    }

    #[test]
    async fn test_validate_invalid_signature_jwt_token() {
        let jwt_generator = setup_jwt_generator(); // Normal JWT setup

        // Generate a valid token with TBID
        let tbid = Some("test_tbid".to_string());
        let valid_token = jwt_generator
            .generate_access_token("client_id", "user_id", "read:documents", tbid.clone())
            .unwrap();

        // Manually alter the signature to create an invalid signature
        let parts: Vec<&str> = valid_token.split('.').collect();
        let invalid_token = format!("{}.{}.invalidsignature", parts[0], parts[1]);

        // Attempt to validate the token with an invalid signature
        let result = jwt_generator.validate_token(
            &invalid_token,
            None, // No audience expected, so we pass None
            "user_id",
            "read:documents",
            tbid.clone(), // Provide the expected tbid
        );

        // Assert that the result is an error and the error is InvalidSignature
        assert_eq!(result.unwrap_err(), TokenError::InvalidSignature);
    }

    #[test]
    async fn test_cleanup_expired_tokens_in_memory() {
        let store = InMemoryTokenStore::new();

        // Get the actual current time
        let current_time = get_current_time().unwrap();

        // Insert tokens into the active tokens map
        {
            let mut active_tokens = store.get_active_tokens().unwrap();
            active_tokens.insert(
                "token1".to_string(),
                Token {
                    value: "token1".to_string(),
                    expiration: current_time + 500, // Valid token, expires in 500 seconds
                    client_id: "client_id_123".to_string(),
                    user_id: "user_id_123".to_string(),
                    tbid: None,
                },
            );
            active_tokens.insert(
                "token2".to_string(),
                Token {
                    value: "token2".to_string(),
                    expiration: current_time - 100, // Expired token
                    client_id: "client_id_456".to_string(),
                    user_id: "user_id_456".to_string(),
                    tbid: None,
                },
            );
            active_tokens.insert(
                "token3".to_string(),
                Token {
                    value: "token3".to_string(),
                    expiration: current_time + 1000, // Valid token, expires in 1000 seconds
                    client_id: "client_id_789".to_string(),
                    user_id: "user_id_789".to_string(),
                    tbid: None,
                },
            );
            active_tokens.insert(
                "token4".to_string(),
                Token {
                    value: "token4".to_string(),
                    expiration: current_time - 200, // Expired token
                    client_id: "client_id_101".to_string(),
                    user_id: "user_id_101".to_string(),
                    tbid: None,
                },
            );
        }

        // Perform cleanup
        store.cleanup_expired_tokens().unwrap();

        // Validate the results after cleanup
        {
            let active_tokens = store.get_active_tokens().unwrap();
            let revoked_tokens = store.get_revoked_tokens().unwrap();

            // Valid tokens should still exist
            assert!(active_tokens.contains_key("token1"));
            assert!(active_tokens.contains_key("token3"));

            // Expired tokens should have been removed from active tokens
            assert!(!active_tokens.contains_key("token2"));
            assert!(!active_tokens.contains_key("token4"));

            // Expired tokens should have been moved to revoked tokens
            assert!(revoked_tokens.contains_key("token2"));
            assert!(revoked_tokens.contains_key("token4"));
        }
    }

    #[test]
    async fn test_cleanup_expired_tokens_with_real_time() {
        let store = InMemoryTokenStore::new();

        // Insert a token that expires in 2 seconds
        let token_valid = "valid_token".to_string();
        let token_expired = "expired_token".to_string();

        let current_time = get_current_time().unwrap();

        {
            let mut active_tokens = store.get_active_tokens().unwrap();
            active_tokens.insert(
                token_valid.clone(),
                Token {
                    value: token_valid.clone(),
                    expiration: current_time + 2, // Expires in 2 seconds
                    client_id: "client_id_123".to_string(),
                    user_id: "user_id_123".to_string(),
                    tbid: None,
                },
            );
            active_tokens.insert(
                token_expired.clone(),
                Token {
                    value: token_expired.clone(),
                    expiration: current_time - 10, // Already expired
                    client_id: "client_id_123".to_string(),
                    user_id: "user_id_123".to_string(),
                    tbid: None,
                },
            );
        }

        // Ensure tokens are present before cleanup
        {
            let active_tokens = store.get_active_tokens().unwrap();
            assert!(active_tokens.contains_key(&token_valid));
            assert!(active_tokens.contains_key(&token_expired));
        }

        // Perform cleanup
        store.cleanup_expired_tokens().unwrap();

        // Check the results after cleanup
        {
            let active_tokens = store.get_active_tokens().unwrap();
            let revoked_tokens = store.get_revoked_tokens().unwrap();

            // Valid token should still exist
            assert!(active_tokens.contains_key(&token_valid));

            // Expired token should have been removed from active tokens
            assert!(!active_tokens.contains_key(&token_expired));

            // Expired token should have been moved to revoked tokens
            assert!(revoked_tokens.contains_key(&token_expired));
        }

        // Wait for the valid token to expire
        sleep(Duration::from_secs(3));

        // Perform another cleanup
        store.cleanup_expired_tokens().unwrap();

        // Validate that the previously valid token is now expired and moved to revoked tokens
        {
            let active_tokens = store.get_active_tokens().unwrap();
            let revoked_tokens = store.get_revoked_tokens().unwrap();

            assert!(!active_tokens.contains_key(&token_valid));
            assert!(revoked_tokens.contains_key(&token_valid));
        }
    }

    #[test]
    async fn test_redis_token_revoked() -> Result<(), TokenError> {
        // Setup Redis connection and RedisTokenStore instance.
        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let store = RedisTokenStore {
            conn: Arc::new(Mutex::new(client.get_connection().unwrap())),
        };

        // Revoke a token using the TokenStore trait method
        let token = "test_token".to_string();
        let exp = get_current_time()? + 3600; // Set expiration 1 hour from now
        store.revoke_token(token.clone(), exp)?;

        // Check if the token is revoked.
        assert_eq!(store.is_token_revoked(&token)?, true);

        Ok(())
    }
    #[test]
    async fn test_redis_cleanup_expired_tokens() -> Result<(), TokenError> {
        // Setup Redis connection and RedisTokenStore instance.
        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let store = RedisTokenStore {
            conn: Arc::new(Mutex::new(client.get_connection().unwrap())),
        };

        // Revoke a token with a short TTL (e.g., 2 seconds)
        let token = "test_cleanup_token".to_string();
        let ttl = 2; // 2 seconds
        let exp = get_current_time()? + ttl;
        store.revoke_token(token.clone(), exp)?;

        // Initially, token should be revoked
        assert_eq!(store.is_token_revoked(&token)?, true);

        // Wait for the TTL to expire
        std::thread::sleep(Duration::from_secs(3));

        // Now, check if the token still exists in Redis
        let mut conn = store.conn.lock().unwrap();
        let exists: bool = redis::cmd("EXISTS").arg(&token).query(&mut *conn).unwrap();

        // After the TTL expires, the token should no longer exist
        assert_eq!(
            exists, false,
            "Token should no longer exist in Redis after TTL expiration."
        );

        Ok(())
    }

    #[test]
    async fn test_jwt_signing_rsa() {
        // Set the JWT_PRIVATE_KEY environment variable for testing purposes
        env::set_var("JWT_PRIVATE_KEY", RSA_PRIVATE_KEY);

        // Initialize JwtTokenGenerator with sample keys
        let token_store = Arc::new(MockTokenStore::new());
        let jwt_generator = JwtTokenGenerator::new(
            RSA_PRIVATE_KEY.as_bytes().to_vec(),
            RSA_PUBLIC_KEY.as_bytes().to_vec(),
            "issuer".to_string(),
            Duration::from_secs(3600),
            Duration::from_secs(7200),
            token_store.clone(),
        );

        let claims = Claims {
            sub: "client_id".to_string(),
            exp: (SystemTime::now() + Duration::from_secs(3600))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            scope: Some("read write".to_string()),
            aud: None,
            client_id: None,
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            iss: Some("issuer".to_string()),
            tbid: Some("mock_tbid".to_string()), // Include TBID
        };

        // Sign the token using JwtTokenGenerator
        let token = jwt_generator
            .sign_token(&claims)
            .expect("Failed to sign with RSA");
        assert!(!token.is_empty());

        // Optionally, decode the token to verify the claims
        let decoding_key = DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY.as_bytes()).unwrap();
        let token_data =
            decode::<Claims>(&token, &decoding_key, &Validation::new(Algorithm::RS256)).unwrap();

        assert_eq!(
            token_data.claims.sub, "client_id",
            "Subject should match the user_id"
        );
        assert_eq!(
            token_data.claims.scope.as_deref(),
            Some("read write"),
            "Scope should match"
        );
        assert_eq!(
            token_data.claims.iss.as_deref(),
            Some("issuer"),
            "Issuer should match"
        );
        assert_eq!(
            token_data.claims.tbid.as_deref(),
            Some("mock_tbid"),
            "TBID should match"
        );
    }
}
