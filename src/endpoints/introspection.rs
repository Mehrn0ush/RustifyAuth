use crate::core::token;
use crate::core::token::Claims;
use crate::core::token::{TokenGenerator, TokenRevocation};
use crate::core::types::TokenError;
use crate::endpoints::introspection::token::Token;
use crate::storage::TokenStore;
use actix_web::body::to_bytes;
use actix_web::{body::BoxBody, web};
use actix_web::{test, App};
use actix_web::{HttpResponse, Responder, ResponseError};
use async_trait::async_trait;
use jsonwebtoken::TokenData;
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl Responder for IntrospectionResponse {
    type Body = BoxBody;

    fn respond_to(self, _: &actix_web::HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok().json(self) // Convert the response to a JSON response
    }
}

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
    req: web::Json<IntrospectionRequest>,
    token_generator: web::Data<Arc<dyn TokenGenerator>>,
    token_store: web::Data<Arc<Mutex<dyn TokenStore>>>,
    client_credentials: Option<(String, String)>,
) -> Result<HttpResponse, TokenError> {
    // Step 1: Authenticate the client (optional but recommended)
    if let Some((client_id, client_secret)) = client_credentials {
        if !authenticate_client(&client_id, &client_secret).await? {
            return Err(TokenError::UnauthorizedClient); // Invalid client credentials
        }
    }

    // Step 2: Check the token type hint and adjust logic accordingly (if provided)
    if let Some(token_type_hint) = &req.token_type_hint {
        let token_store = token_store.get_ref().lock().unwrap();
        if token_type_hint == "refresh_token" && token_store.is_token_revoked(&req.token) {
            return Ok(HttpResponse::Ok().json(inactive_token_response())); // Revoked refresh token
        }
    }

    // Step 3: Validate the token using the token generator (check for validity)
    let token_data = token_generator
        .validate_token(&req.token, None, "", "", None) // Adjust based on your audience/sub check
        .map_err(|_| TokenError::InvalidToken)?;

    let claims = token_data.claims;
    // Step 4: Check if the token is expired
    let current_timestamp: u64 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    if (claims.exp as u64) < current_timestamp {
        return Ok(HttpResponse::Ok().json(inactive_token_response())); // Expired token
    }

    //step 5: Check if the token is revoked
    let token_store = token_store.get_ref().lock().unwrap();
    if token_store.is_token_revoked(&req.token) {
        return Ok(HttpResponse::Ok().json(inactive_token_response()));
    }

    //step 6: Return token information in the response if valid
    // Construct the introspection response
    let introspection_response = IntrospectionResponse {
        active: true, // Set to true or false based on your validation logic
        scope: claims.scope.clone(),
        client_id: claims.client_id.clone(),
        username: Some(claims.sub.clone()),
        exp: Some(claims.exp as u64),
        sub: Some(claims.sub.clone()),
    };

    // Return the HTTP response with the introspection response serialized as JSON
    Ok(HttpResponse::Ok().json(introspection_response))
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
        tbid: Option<String>,
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
        tbid: Option<String>,
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
            tbid: None,
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
        _tbid: Option<String>,
    ) -> Result<String, TokenError> {
        // Mocking access token generation
        Ok("mock_access_token".to_string())
    }

    fn generate_refresh_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
        _tbid: Option<String>,
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
                tbid: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;
    use actix_web::{test, web, App, HttpResponse};
    use serde_json::json;

    #[actix_web::test]
    async fn test_active_token() {
        use actix_web::body::to_bytes;
        use actix_web::{test, web, App, HttpResponse};
        use serde_json::json;

        // Box and coerce the mock implementations to trait objects
        let token_generator: Arc<dyn TokenGenerator> = Arc::new(MockTokenGeneratorintro::new());
        let token_store: Arc<dyn TokenStore> = Arc::new(MockTokenStore::new());

        let token = "valid_access_token";

        let introspection_request = IntrospectionRequest {
            token: token.to_string(),
            token_type_hint: None,
        };

        // Wrap the request and data appropriately
        let req = web::Json(introspection_request);
        let token_generator_data = web::Data::new(token_generator.clone());
        let token_store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(MockTokenStore::new()));
        let token_store_data = web::Data::new(token_store.clone());

        // Pass the boxed trait objects to the function
        let response_result =
            introspect_token(req, token_generator_data, token_store_data, None).await;

        assert!(response_result.is_ok());
        let response = response_result.unwrap();

        // Extract the IntrospectionResponse from the HttpResponse
        let body = to_bytes(response.into_body()).await.unwrap();
        let introspection_response: IntrospectionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(introspection_response.active, true);
        assert_eq!(introspection_response.client_id.unwrap(), "client_id_123");
        assert_eq!(introspection_response.username.unwrap(), "user_123");
        assert!(introspection_response.exp.is_some());
        assert!(introspection_response.scope.is_some());
    }

    #[actix_web::test]
    async fn test_revoked_token() {
        let token_generator: Arc<dyn TokenGenerator> = Arc::new(MockTokenGeneratorintro::new());
        let token_store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(MockTokenStore::new()));

        let token = "revoked_access_token";

        // Lock the token store to mutate it
        {
            let mut token_store = token_store.lock().unwrap();
            token_store.revoke_access_token(token);
        }

        let introspection_request = IntrospectionRequest {
            token: token.to_string(),
            token_type_hint: None,
        };

        let req = web::Json(introspection_request);
        let token_generator_data = web::Data::new(token_generator.clone());
        let token_store_data = web::Data::new(token_store.clone());

        let response_result =
            introspect_token(req, token_generator_data, token_store_data, None).await;

        assert!(response_result.is_ok());
        let response = response_result.unwrap();

        let body = to_bytes(response.into_body()).await.unwrap();
        let introspection_response: IntrospectionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(introspection_response.active, false);
        assert!(introspection_response.client_id.is_none());
        assert!(introspection_response.username.is_none());
        assert!(introspection_response.exp.is_none());
    }

    #[tokio::test]
    async fn test_expired_token() {
        // Create the mock token generator and store
        let mock_token_generator = MockTokenGeneratorintro::new(); // Use concrete type first
        let token_store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(MockTokenStore::new()));

        let token = "expired_access_token";
        mock_token_generator.set_token_expired(token); // Now we can call this method on the concrete type

        // After using set_token_expired, we can wrap the mock_token_generator in Arc<dyn TokenGenerator>
        let token_generator: Arc<dyn TokenGenerator> = Arc::new(mock_token_generator);

        let introspection_request = IntrospectionRequest {
            token: token.to_string(),
            token_type_hint: None,
        };

        // Wrap the request and data appropriately
        let req = web::Json(introspection_request);
        let token_generator_data = web::Data::new(token_generator.clone());
        let token_store_data = web::Data::new(token_store.clone());

        // Call introspect_token with the proper types
        let response_result =
            introspect_token(req, token_generator_data, token_store_data, None).await;

        assert!(
            response_result.is_ok(),
            "Expected Ok response for expired token introspection"
        );
        let response = response_result.unwrap();

        let body = to_bytes(response.into_body()).await.unwrap();
        let introspection_response: IntrospectionResponse = serde_json::from_slice(&body).unwrap();

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
        // Use Arc directly without Box
        let token_generator: Arc<dyn TokenGenerator> = Arc::new(MockTokenGeneratorintro::new());
        let token_store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(MockTokenStore::new()));

        let token = "valid_access_token";
        let client_credentials = Some((
            "valid_client_id".to_string(),
            "valid_client_secret".to_string(),
        ));

        let introspection_request = IntrospectionRequest {
            token: token.to_string(),
            token_type_hint: None,
        };

        // Wrap the request and data appropriately
        let req = web::Json(introspection_request);
        let token_generator_data = web::Data::new(token_generator.clone());
        let token_store_data = web::Data::new(token_store.clone());

        // Call introspect_token with the proper types
        let response_result = introspect_token(
            req,
            token_generator_data,
            token_store_data,
            client_credentials,
        )
        .await;

        assert!(response_result.is_ok());
        let response = response_result.unwrap();

        let body = to_bytes(response.into_body()).await.unwrap();
        let introspection_response: IntrospectionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(introspection_response.active, true);
        assert!(introspection_response.client_id.is_some());
        assert!(introspection_response.username.is_some());
    }

    //Invalid Client Credentials Test
    //This test checks if the introspection fails when invalid client credentials are provided.
    #[actix_web::test]
    async fn test_invalid_client_credentials() {
        // Create token generator and store
        let token_generator: Arc<dyn TokenGenerator> = Arc::new(MockTokenGeneratorintro::new());
        let token_store: Arc<Mutex<dyn TokenStore>> = Arc::new(Mutex::new(MockTokenStore::new()));

        let token = "valid_access_token";
        let client_credentials = Some((
            "invalid_client_id".to_string(),
            "invalid_client_secret".to_string(),
        ));

        let introspection_request = IntrospectionRequest {
            token: token.to_string(),
            token_type_hint: None,
        };

        let req = web::Json(introspection_request);
        let token_generator_data = web::Data::new(token_generator.clone());
        let token_store_data = web::Data::new(token_store.clone());

        let response_result = introspect_token(
            req,
            token_generator_data,
            token_store_data,
            client_credentials,
        )
        .await;

        assert!(response_result.is_err());
        if let Err(TokenError::UnauthorizedClient) = response_result {
            // Test passes if we receive UnauthorizedClient error
            assert!(true);
        } else {
            assert!(false, "Expected unauthorized client error");
        }
    }
}
