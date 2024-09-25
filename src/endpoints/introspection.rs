use crate::core::token;
use crate::core::token::Claims;
use crate::core::token::{TokenGenerator, TokenRevocation};
use crate::core::types::TokenError;
use crate::endpoints::introspection::token::Token;
use crate::storage::TokenStore;
use async_trait::async_trait;
use jsonwebtoken::TokenData;
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<String>, // Optional hint about token type (access or refresh)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,          // Whether the token is valid
    pub scope: Option<String>, // Scope of the token
    pub client_id: Option<String>,
    pub username: Option<String>, // If available
    pub exp: Option<u64>,         // Expiration time in seconds since epoch
    pub sub: Option<String>,      // Subject
}

// Inactive token response for invalid or revoked tokens
pub fn inactive_token_response() -> IntrospectionResponse {
    IntrospectionResponse {
        active: false,
        scope: None,
        client_id: None,
        username: None,
        exp: None,
        sub: None,
    }
}
// Main introspection function
pub async fn introspect_token(
    req: IntrospectionRequest,
    token_generator: Arc<dyn TokenGenerator>, // The token generator (JWT or Opaque)
    token_store: Arc<dyn TokenStore>,         // TokenStore to check for revocation
    client_credentials: Option<(String, String)>, // Optional client credentials (for authentication)
) -> Result<IntrospectionResponse, TokenError> {
    // Step 1: Authenticate the client (optional but recommended)
    if let Some((client_id, client_secret)) = client_credentials {
        if !authenticate_client(&client_id, &client_secret).await? {
            return Err(TokenError::UnauthorizedClient); // Invalid client credentials
        }
    }

    // Step 2: Check the token type hint and adjust logic accordingly (if provided)
    if let Some(token_type_hint) = &req.token_type_hint {
        if token_type_hint == "refresh_token" && token_store.is_token_revoked(&req.token) {
            return Ok(inactive_token_response()); // Revoked refresh token
        }
    }

    // Step 3: Validate the token using the token generator (check for validity)
    let token_data = token_generator
        .validate_token(&req.token, None, "", "") // Adjust based on your audience/sub check
        .map_err(|_| TokenError::InvalidToken)?;

    let claims = token_data.claims;
    // Step 4: Check if the token is expired
    let current_timestamp: u64 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    if (claims.exp as u64) < current_timestamp {
        return Ok(inactive_token_response()); // Expired token should return Inactive Response
    }

    //step 5: Check if the token is revoked
    if token_store.is_token_revoked(&req.token) {
        return Ok(inactive_token_response());
    }

    //step 6: Return token information in the response if valid
    Ok(IntrospectionResponse {
        active: true, // Only return active: true if token is neither expired nor revoked
        scope: claims.scope.clone(),
        client_id: claims.client_id.clone(),
        username: Some(claims.sub.clone()), // Using subject as username for simplicity
        exp: Some(claims.exp as u64),
        sub: Some(claims.sub.clone()),
    })
}
// Helper function to authenticate clients
async fn authenticate_client(client_id: &str, client_secret: &str) -> Result<bool, TokenError> {
    // Simulate client authentication (implement your own logic here)
    if client_id == "valid_client_id" && client_secret == "valid_client_secret" {
        Ok(true)
    } else {
        Ok(false)
    }
}

// To simulate token validation and storage for these tests,
//we should mock implementations for TokenGenerator and TokenStore.
//MockTokenGenerator simulates the behavior of a real token generator by allowing you to "expire" tokens manually for testing purposes.

pub struct MockTokenGeneratorintro {
    tokens: Mutex<Vec<String>>,
    expired_tokens: Mutex<Vec<String>>,
}

impl MockTokenGeneratorintro {
    pub fn new() -> Self {
        MockTokenGeneratorintro {
            tokens: Mutex::new(vec![]),
            expired_tokens: Mutex::new(vec![]),
        }
    }

    pub fn set_token_expired(&self, token: &str) {
        self.expired_tokens.lock().unwrap().push(token.to_string());
    }
}

//MockTokenStore simulates the revocation of tokens, allowing you to test revoked token scenarios.
#[async_trait]
impl TokenGenerator for MockTokenGeneratorintro {
    fn access_token_lifetime(&self) -> Duration {
        // Implement a mock access token lifetime here
        Duration::from_secs(3600) // Example: 1 hour
    }

    fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<(String, String), TokenError> {
        // Implement a mock refresh token exchange logic
        Ok((
            "mock_access_token".to_string(),
            "mock_new_refresh_token".to_string(),
        ))
    }
    fn validate_token(
        &self,
        token: &str,
        _aud: Option<&str>,
        _sub: &str,
        _required_scope: &str,
    ) -> Result<TokenData<Claims>, TokenError> {
        let is_expired = self
            .expired_tokens
            .lock()
            .unwrap()
            .contains(&token.to_string());

        // Simulate the current time and check if the token is expired
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = Claims {
            sub: "user_123".to_string(),
            client_id: Some("client_id_123".to_string()),
            exp: if is_expired {
                (current_timestamp - 1000).try_into().unwrap() // Convert u64 to usize
            } else {
                (current_timestamp + 3600).try_into().unwrap() // Convert u64 to usize
            },
            iat: current_timestamp.try_into().unwrap(), // Convert u64 to usize
            iss: Some("test_issuer".to_string()),
            aud: None,
            scope: Some("read".to_string()),
        };

        //Debugging output to track expiration
        println!(
            "Current timestamp {}, Claims exp: {}",
            current_timestamp, claims.exp
        );

        // If the token has expired based on the timestamp, return an error
        if claims.exp < (current_timestamp as u64) {
            return Ok(TokenData {
                header: Header {
                    alg: Algorithm::RS256,
                    ..Default::default()
                },
                claims,
            });
        }

        Ok(TokenData {
            header: Header {
                alg: Algorithm::RS256,
                ..Default::default()
            },
            claims,
        })
    }

    fn generate_access_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
    ) -> Result<String, TokenError> {
        // Mocking access token generation
        Ok("mock_access_token".to_string())
    }

    fn generate_refresh_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
    ) -> Result<String, TokenError> {
        // Mocking refresh token generation
        Ok("mock_refresh_token".to_string())
    }
}

pub struct MockTokenStore {
    pub access_tokens: Mutex<HashMap<String, Token>>,
    pub revoked_tokens: Mutex<Vec<String>>,
    pub revoked_refresh_tokens: Mutex<Vec<String>>,
    pub refresh_tokens: Mutex<HashMap<String, (String, String, u64)>>,
}

impl MockTokenStore {
    pub fn new() -> Self {
        MockTokenStore {
            revoked_tokens: Mutex::new(vec![]),
            revoked_refresh_tokens: Mutex::new(vec![]),
            refresh_tokens: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(HashMap::new()),
        }
    }

    pub fn revoke_access_token(&self, token: &str) {
        self.revoked_tokens.lock().unwrap().push(token.to_string());
    }
}

impl TokenStore for MockTokenStore {
    fn store_access_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError> {
        let mut access_tokens = self.access_tokens.lock().unwrap();
        access_tokens.insert(
            token.to_string(),
            Token {
                value: token.to_string(),
                expiration: exp,
                client_id: client_id.to_string(),
                user_id: user_id.to_string(),
            },
        );
        Ok(())
    }
    fn revoke_access_token(&mut self, token: &str) -> bool {
        let mut revoked_tokens = self.revoked_tokens.lock().unwrap();
        revoked_tokens.push(token.to_string());
        true
    }

    fn revoke_refresh_token(&mut self, token: &str) -> bool {
        let mut revoked_refresh_tokens = self.revoked_refresh_tokens.lock().unwrap();
        revoked_refresh_tokens.push(token.to_string());
        true
    }
    fn is_token_revoked(&self, token: &str) -> bool {
        self.revoked_tokens
            .lock()
            .unwrap()
            .contains(&token.to_string())
    }

    fn is_refresh_token_revoked(&self, token: &str) -> bool {
        let revoked_refresh_tokens = self.revoked_refresh_tokens.lock().unwrap();
        revoked_refresh_tokens.contains(&token.to_string())
    }

    fn store_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError> {
        let mut refresh_tokens = self.refresh_tokens.lock().unwrap(); // Lock the mutex for safe mutation
        refresh_tokens.insert(
            token.to_string(),
            (client_id.to_string(), user_id.to_string(), exp),
        );
        Ok(())
    }

    fn validate_refresh_token(
        &mut self,
        token: &str,
        client_id: &str,
    ) -> Result<(String, u64), TokenError> {
        let refresh_tokens = self.refresh_tokens.lock().unwrap(); // Use Mutex for safe access
        if let Some((stored_client_id, user_id, exp)) = refresh_tokens.get(token) {
            if stored_client_id == client_id {
                return Ok((user_id.clone(), *exp));
            } else {
                return Err(TokenError::InvalidClient);
            }
        }
        Err(TokenError::InvalidToken)
    }

    fn rotate_refresh_token(
        &mut self,
        old_token: &str,
        new_token: &str,
        client_id: &str,
        user_id: &str,
        exp: u64,
    ) -> Result<(), TokenError> {
        // Revoke old refresh token
        if !self.revoke_refresh_token(old_token) {
            return Err(TokenError::InvalidToken);
        }

        // Lock the refresh_tokens mutex
        let mut refresh_tokens = self.refresh_tokens.lock().unwrap();
        // Store the new refresh token
        refresh_tokens.insert(
            new_token.to_string(),
            (client_id.to_string(), user_id.to_string(), exp),
        );

        Ok(())
    }
}

// We will cover the following scenarios:
// Active tokens: Verifying that a valid token returns an active response with correct metadata.
// Revoked tokens: Ensuring revoked tokens are marked as inactive.
// Expired tokens: Validating that expired tokens are marked as inactive.
// Client authentication: Testing the introspection endpoint with and without valid client credentials.

#[tokio::test]
async fn test_active_token() {
    let token_generator = Arc::new(MockTokenGeneratorintro::new()); // Mock implementation of TokenGenerator
    let token_store = Arc::new(MockTokenStore::new()); // Mock implementation of TokenStore

    let token = "valid_access_token";

    let introspection_request = IntrospectionRequest {
        token: token.to_string(),
        token_type_hint: None,
    };

    let response = introspect_token(
        introspection_request,
        token_generator.clone(),
        token_store.clone(),
        None, // No client credentials for this test
    )
    .await;

    assert!(response.is_ok());
    let introspection_response = response.unwrap();

    assert_eq!(introspection_response.active, true);
    assert_eq!(introspection_response.client_id.unwrap(), "client_id_123");
    assert_eq!(introspection_response.username.unwrap(), "user_123");
    assert!(introspection_response.exp.is_some());
    assert!(introspection_response.scope.is_some());
}

#[tokio::test]
async fn test_revoked_token() {
    let token_generator = Arc::new(MockTokenGeneratorintro::new()); // Mock implementation of TokenGenerator
    let token_store = Arc::new(MockTokenStore::new()); // Mock implementation of TokenStore

    // Mark the token as revoked in the token store
    let token = "revoked_access_token";
    token_store.revoke_access_token(token);

    let introspection_request = IntrospectionRequest {
        token: token.to_string(),
        token_type_hint: None,
    };

    let response = introspect_token(
        introspection_request,
        token_generator.clone(),
        token_store.clone(),
        None,
    )
    .await;

    assert!(response.is_ok());
    let introspection_response = response.unwrap();

    assert_eq!(introspection_response.active, false);
    assert!(introspection_response.client_id.is_none());
    assert!(introspection_response.username.is_none());
    assert!(introspection_response.exp.is_none());
}

#[tokio::test]
async fn test_expired_token() {
    let token_generator = Arc::new(MockTokenGeneratorintro::new()); // Mock implementation of TokenGenerator
    let token_store = Arc::new(MockTokenStore::new()); // Mock implementation of TokenStore

    let token = "expired_access_token";

    // Simulate an expired token in the token generator
    token_generator.set_token_expired(token); // Mark this token as expired

    let introspection_request = IntrospectionRequest {
        token: token.to_string(),
        token_type_hint: None,
    };

    let response = introspect_token(
        introspection_request,
        token_generator.clone(),
        token_store.clone(),
        None,
    )
    .await;

    //Debugging to see the response
    println!("Response: {:?}", response);

    // Ensure the response is a valid IntrospectionResponse but shows inactive
    assert!(
        response.is_ok(),
        "Expected Ok response for expired token introspection"
    );
    let introspection_response = response.unwrap();
    assert_eq!(
        introspection_response.active, false,
        "Expired token should be inactive"
    );
}

#[tokio::test]
async fn test_expired_token_2() {
    let token_generator = Arc::new(MockTokenGeneratorintro::new()); // Mock implementation of TokenGenerator
    let token_store = Arc::new(MockTokenStore::new()); // Mock implementation of TokenStore

    let token = "expired_access_token_2";

    // Simulate an expired token in the token generator
    token_generator.set_token_expired(token); // Mark this token as expired

    let introspection_request = IntrospectionRequest {
        token: token.to_string(),
        token_type_hint: None,
    };

    let response = introspect_token(
        introspection_request,
        token_generator.clone(),
        token_store.clone(),
        None,
    )
    .await;

    // Ensure the response is a valid IntrospectionResponse but shows inactive
    assert!(
        response.is_ok(),
        "Expected Ok response for expired token introspection"
    );
    let introspection_response = response.unwrap();
    assert_eq!(
        introspection_response.active, false,
        "Expired token should be inactive"
    );
}

//Client Authentication Tests
// These tests validate that only authorized clients can introspect tokens, and unauthorized clients are denied access.

// 4.1 Valid Client Credentials Test
// This test checks if the introspection succeeds when valid client credentials are provided.

#[tokio::test]
async fn test_valid_client_credentials() {
    let token_generator = Arc::new(MockTokenGeneratorintro::new()); // Mock implementation of TokenGenerator
    let token_store = Arc::new(MockTokenStore::new()); // Mock implementation of TokenStore

    let token = "valid_access_token";
    let client_credentials = Some((
        "valid_client_id".to_string(),
        "valid_client_secret".to_string(),
    ));

    let introspection_request = IntrospectionRequest {
        token: token.to_string(),
        token_type_hint: None,
    };

    let response = introspect_token(
        introspection_request,
        token_generator.clone(),
        token_store.clone(),
        client_credentials,
    )
    .await;

    assert!(response.is_ok());
    let introspection_response = response.unwrap();

    assert_eq!(introspection_response.active, true);
    assert!(introspection_response.client_id.is_some());
    assert!(introspection_response.username.is_some());
}

//Invalid Client Credentials Test
//This test checks if the introspection fails when invalid client credentials are provided.
#[tokio::test]
async fn test_invalid_client_credentials() {
    let token_generator = Arc::new(MockTokenGeneratorintro::new()); // Mock implementation of TokenGenerator
    let token_store = Arc::new(MockTokenStore::new()); // Mock implementation of TokenStore

    let token = "valid_access_token";
    let client_credentials = Some((
        "invalid_client_id".to_string(),
        "invalid_client_secret".to_string(),
    ));

    let introspection_request = IntrospectionRequest {
        token: token.to_string(),
        token_type_hint: None,
    };

    let response = introspect_token(
        introspection_request,
        token_generator.clone(),
        token_store.clone(),
        client_credentials,
    )
    .await;

    assert!(response.is_err());
    if let Err(TokenError::UnauthorizedClient) = response {
        // Test passes if we receive UnauthorizedClient error
        assert!(true);
    } else {
        assert!(false, "Expected unauthorized client error");
    }
}
