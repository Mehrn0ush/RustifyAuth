use crate::core::pkce::{validate_pkce_challenge, PkceError};
use crate::core::token::Claims;
use crate::core::token::TokenGenerator;
use crate::core::types::{TokenError, TokenResponse};
use crate::endpoints::introspection::MockTokenGeneratorintro;
use crate::storage::memory::{CodeStore, MemoryCodeStore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
//use std::sync::Mutex;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use super::pkce::generate_pkce_challenge;

// Error types for authorization flow
#[derive(Debug, PartialEq)]
pub enum AuthorizationError {
    InvalidCode,
    ExpiredCode,
    InvalidPKCE,
    TokenGenerationError,
    InvalidGrant,
    InvalidTotpCode,
    RateLimited,
    InvalidScope,
}

// Struct for managing authorization code flow with PKCE and tokens
pub struct AuthorizationCodeFlow {
    pub code_store: Arc<Mutex<dyn CodeStore>>, // Store for authorization codes
    pub token_generator: Arc<dyn TokenGenerator>, // Token generation (JWT or Opaque)
    pub code_lifetime: Duration,               // Duration for code validity
    pub allowed_scopes: Vec<String>,           // List of allowed scopes
}

// AuthorizationCode structure to represent and authorization code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub pkce_challenge: String,
    pub scope: String, // Store the requested scopes
    pub expires_at: std::time::SystemTime,
}

// Implement the From trait for automatic conversion
impl From<PkceError> for TokenError {
    fn from(_: PkceError) -> Self {
        TokenError::InvalidPKCEChallenge
    }
}

impl AuthorizationCodeFlow {
    pub fn new(
        code_store: Arc<Mutex<dyn CodeStore>>,
        token_generator: Arc<dyn TokenGenerator>, // Include token_generator here
        code_lifetime: Duration,
        allowed_scopes: Vec<String>,
    ) -> Self {
        AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime,
            allowed_scopes,
        }
    }

    pub fn validate_pkce_challenge(
        stored_challenge: &str,
        verifier: &str,
    ) -> Result<(), PkceError> {
        // Add logging to debug PKCE challenge and verifier
        eprintln!("Stored PKCE Challenge: {}", stored_challenge);
        eprintln!("Provided PKCE Verifier: {}", verifier);

        // Step 1: Hash the verifier using SHA256
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hashed_verifier = hasher.finalize();

        // Step 2: Encode the hash using Base64URL encoding (without padding)
        let generated_challenge = URL_SAFE_NO_PAD.encode(&hashed_verifier);

        // Step 3: Compare the generated challenge with the stored challenge
        if constant_time_eq::constant_time_eq(
            stored_challenge.as_bytes(),
            generated_challenge.as_bytes(),
        ) {
            Ok(())
        } else {
            Err(PkceError::InvalidVerifier)
        }
    }

    // Generates and stores an authorization code along with the PKCE challenge
    pub fn generate_authorization_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
        scope: &str,
    ) -> Result<AuthorizationCode, AuthorizationError> {
        // Validate the scope
        if !self.allowed_scopes.contains(&scope.to_string()) {
            return Err(AuthorizationError::InvalidScope);
        }
        // Generate the PKCE challenge
        let pkce_challenge =
            generate_pkce_challenge(pkce_verifier).map_err(|_| AuthorizationError::InvalidPKCE)?;
        // Generate the authorization code
        let code = generate_random_code(); // We could implement this or use a library
        let expires_at = SystemTime::now() + self.code_lifetime;
        let authorization_code = AuthorizationCode {
            code: code.clone(),
            client_id: client_id.to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            pkce_challenge: pkce_challenge.to_owned(),
            scope: scope.to_owned(), // save the scope
            expires_at,
        };

        let mut code_store = self.code_store.lock().unwrap();
        code_store.store_code(authorization_code.clone());

        Ok(authorization_code)
    }

    // Exchanges an authorization code for tokens (access & refresh)
    pub fn exchange_code_for_token(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<TokenResponse, TokenError> {
        eprintln!(
            "Attempting to retrieve the authorization code for: {}",
            code
        );
        let mut code_store = self.code_store.lock().unwrap();
        let stored_code = code_store.retrieve_code(code).ok_or_else(|| {
            eprintln!("InvalidGrant: Code not found.");
            TokenError::InvalidGrant
        })?;
        eprintln!(
            "Authorization code retrieved successfully: {:?}",
            stored_code
        );

        // If the code is revoked, return an error
        if code_store.is_code_revoked(code) {
            eprintln!("InvalidGrant: Code is revoked.");
            return Err(TokenError::InvalidGrant);
        }

        // Check if the code is expired
        if SystemTime::now() > stored_code.expires_at {
            eprintln!("InvalidGrant: code is expired.");
            return Err(TokenError::InvalidGrant);
        }

        // Validate the PKCE challenge

        match validate_pkce_challenge(&stored_code.pkce_challenge, pkce_verifier) {
            Ok(_) => eprintln!("PKCE validation succeeded."),
            Err(e) => {
                eprintln!("PKCE validation failed: {:?}", e);
                return Err(TokenError::InvalidPKCEChallenge);
            }
        };

        // Revoke the authorization code after successful use

        let code_revoke_result = code_store.revoke_code(code);
        if !code_revoke_result {
            eprintln!("Code has already been used or revoked");
            return Err(TokenError::InvalidGrant); // The code was already used or revoked
        }
        eprintln!("Code revoked successfully.");

        // Generate new access and refresh tokens
        let access_token = self.token_generator.generate_access_token(
            &stored_code.client_id,
            &stored_code.code,
            &stored_code.scope,
        )?;

        let refresh_token = self.token_generator.generate_refresh_token(
            &stored_code.client_id,
            &stored_code.code,
            &stored_code.scope,
        )?;

        eprintln!("Token generation succeeded.");

        // Construct the token response
        Ok(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600, // Set the expiration time for the access token (in seconds)
            scope: Some(stored_code.scope),
        })
    }
}

fn generate_random_code() -> String {
    use rand::Rng;
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    code
}

//unit tests for the AuthorizationCodeFlow struct. These tests will validate proper behavior for scenarios such as generating and exchanging codes, handling expired or invalid codes, and handling PKCE challenge mismatches
/* Unit Tests for AuthorizationCodeFlow:
Test: Generate Authorization Code
Ensure an authorization code is generated correctly, including scope and other fields.

Test: Exchange Code for Token (Valid Case)
Ensure the code is generated correctly with the expected properties.
Ensure valid authorization code and PKCE verifier can be exchanged for tokens (access and refresh).

Test: Exchange Code for Token (Expired Code)
Ensure that attempting to exchange an expired authorization code results in an error.
Also, Test that an expired code returns an appropriate error.

Test: Invalid PKCE Verifier
Ensure that providing an incorrect PKCE verifier returns an error.

Test: Invalid Authorization Code.
Check the behavior when an invalid or non-existent code is provided.


Test: Exchange Code for Token (Invalid PKCE Verifier)
Ensure that an invalid PKCE verifier results in an error when exchanging a code.

Test: Exchange Code for Token (Invalid Code)

Ensure that an invalid authorization code results in an error when exchanging for tokens.
Test: Exchange Code for Token (Expired Token Generation)

Ensure that generated tokens adhere to expected expiration rules. */

// MockTokenGenerator struct (basic mock)
#[derive(Default)]
pub struct MockTokenGenerator;

// MockTokenGeneratorWithExpiry struct (with token expiration simulation)
pub struct MockTokenGeneratorWithExpiry {
    access_token_lifetime: Duration,
    refresh_token_lifetime: Duration,
    token_creation_times: Mutex<HashMap<String, SystemTime>>, // Map tokens to their creation times
}

// Implement the Clone trait for MockTokenGeneratorWithExpiry
impl Clone for MockTokenGeneratorWithExpiry {
    fn clone(&self) -> Self {
        MockTokenGeneratorWithExpiry {
            access_token_lifetime: self.access_token_lifetime,
            refresh_token_lifetime: self.refresh_token_lifetime,
            token_creation_times: Mutex::new(self.token_creation_times.lock().unwrap().clone()), // Clone the Mutex content
        }
    }
}

// Implement constructor for MockTokenGeneratorWithExpiry
impl MockTokenGeneratorWithExpiry {
    pub fn new(access_token_lifetime: Duration, refresh_token_lifetime: Duration) -> Self {
        MockTokenGeneratorWithExpiry {
            access_token_lifetime,
            refresh_token_lifetime,
            token_creation_times: Mutex::new(HashMap::new()),
        }
    }
}

// Implement TokenGenerator for MockTokenGenerator (basic mock)
impl TokenGenerator for MockTokenGenerator {
    fn access_token_lifetime(&self) -> Duration {
        Duration::from_secs(3600) // Example: 1 hour
    }

    fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<(String, String), TokenError> {
        Ok((
            "mock_access_token".to_string(),
            "mock_new_refresh_token".to_string(),
        ))
    }
    fn generate_access_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
    ) -> Result<String, TokenError> {
        Ok("mock_access_token".to_string())
    }

    fn generate_refresh_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
    ) -> Result<String, TokenError> {
        Ok("mock_refresh_token".to_string())
    }

    fn validate_token(
        &self,
        token: &str,
        _aud: Option<&str>,
        sub: &str,
        required_scope: &str,
    ) -> Result<TokenData<Claims>, TokenError> {
        if token == "mock_access_token" {
            let now = SystemTime::now();

            // Mocked Claims with scope and subject (sub)

            let claims = Claims {
                sub: sub.to_string(),
                exp: (now + Duration::from_secs(3600))
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                scope: Some(required_scope.to_string()),
                aud: Some("example_aud".to_string()),
                client_id: Some("client_id".to_string()), // mock client_id validation
                iat: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                iss: Some("example_issuer".to_string()),
            };

            // Return valid token data

            Ok(TokenData {
                header: Default::default(),
                claims,
            })
        } else {
            Err(TokenError::InvalidToken)
        }
    }
}

// Implement TokenGenerator for MockTokenGeneratorWithExpiry (with expiration)
impl TokenGenerator for MockTokenGeneratorWithExpiry {
    fn generate_access_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
    ) -> Result<String, TokenError> {
        let token = "mock_access_token".to_string();
        let now = SystemTime::now();

        self.token_creation_times
            .lock()
            .unwrap()
            .insert(token.clone(), now);

        Ok(token)
    }

    fn generate_refresh_token(
        &self,
        _client_id: &str,
        _user_id: &str,
        _scope: &str,
    ) -> Result<String, TokenError> {
        let token = "mock_refresh_token".to_string();
        let now = SystemTime::now();

        self.token_creation_times
            .lock()
            .unwrap()
            .insert(token.clone(), now);

        Ok(token)
    }

    fn validate_token(
        &self,
        token: &str,
        _aud: Option<&str>,
        sub: &str,
        required_scope: &str,
    ) -> Result<TokenData<Claims>, TokenError> {
        if token == "mock_access_token" {
            let now = SystemTime::now();

            // Ensure the sub (client_id) and required_scope match the expected values
            if sub == "client_id" && required_scope == "read:documents" {
                return Ok(TokenData {
                    header: Default::default(),
                    claims: Claims {
                        sub: sub.to_string(),
                        exp: (now + Duration::from_secs(3600))
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        scope: Some(required_scope.to_string()),
                        aud: Some("example_aud".to_string()),
                        client_id: Some(sub.to_string()), // Mock client_id validation
                        iat: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                        iss: Some("example_issuer".to_string()),
                    },
                });
            }
        }

        let creation_time = self
            .token_creation_times
            .lock()
            .unwrap()
            .get(token)
            .copied();

        if let Some(creation_time) = creation_time {
            let elapsed = creation_time.elapsed().unwrap();

            if token == "mock_access_token" && elapsed <= self.access_token_lifetime {
                // Token is still valid
                return Ok(TokenData {
                    header: Default::default(),
                    claims: Claims {
                        sub: "user_id".to_string(),
                        exp: (creation_time + self.access_token_lifetime)
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        scope: Some("read:documents".to_string()),
                        aud: Some("example_aud".to_string()),
                        client_id: Some("example_client_id".to_string()),
                        iat: creation_time.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                        iss: Some("example_issuer".to_string()),
                    },
                });
            } else if token == "mock_refresh_token" && elapsed <= self.refresh_token_lifetime {
                return Ok(TokenData {
                    header: Default::default(),
                    claims: Claims {
                        sub: "user_id".to_string(),
                        exp: (creation_time + self.refresh_token_lifetime)
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        scope: Some("read:documents".to_string()),
                        aud: Some("example_aud".to_string()),
                        client_id: Some("example_client_id".to_string()),
                        iat: creation_time.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                        iss: Some("example_issuer".to_string()),
                    },
                });
            } else {
                Err(TokenError::InvalidToken)
            }
        } else {
            Err(TokenError::InvalidToken)
        }
    }
    fn access_token_lifetime(&self) -> Duration {
        // Mock value for access token lifetime
        Duration::from_secs(3600) // 1 hour
    }

    fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<(String, String), TokenError> {
        // Mock implementation of refresh token exchange
        Ok((
            "mock_access_token".to_string(),
            "mock_refresh_token".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::token::Claims;
    use crate::core::token::{InMemoryTokenStore, JwtTokenGenerator};
    use crate::storage::memory;
    use crate::storage::memory::MemoryCodeStore;
    use crate::storage::memory::MemoryTokenStoreTrait;
    use jsonwebtoken::TokenData;
    use rand::{distributions::Alphanumeric, Rng};
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    // Test for generating a valid authorization code
    #[test]
    fn test_generate_authorization_code() {
        use rand::{distributions::Alphanumeric, Rng};

        // Declare and instantiate the token store
        let token_store = Arc::new(InMemoryTokenStore::new());

        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        let token_generator = Arc::new(JwtTokenGenerator {
            private_key: vec![],
            public_key: vec![],
            issuer: "test-issuer".to_string(),
            access_token_lifetime: Duration::from_secs(3600),
            refresh_token_lifetime: Duration::from_secs(86400),
            token_store: token_store.clone(),
        });

        // Define allowed scopes
        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];

        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        let scope = "read:documents";

        // Generate a valid PKCE verifier
        let pkce_verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50) // Length between 43 and 128
            .map(char::from)
            .collect();

        let auth_code = auth_code_flow
            .generate_authorization_code("client_id", "redirect_uri", &pkce_verifier, scope)
            .unwrap();

        assert!(!auth_code.code.is_empty());
        assert_eq!(auth_code.scope, scope);
        assert_eq!(auth_code.client_id, "client_id");
        assert_eq!(auth_code.redirect_uri, "redirect_uri");
    }

    // Test for successful token exchange
    #[test]
    fn test_exchange_valid_code_for_token() {
        use rand::{distributions::Alphanumeric, Rng};

        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];

        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        let token_generator = Arc::new(MockTokenGenerator);

        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        // Generate a valid PKCE verifier
        let pkce_verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50)
            .map(char::from)
            .collect();

        let auth_code = auth_code_flow
            .generate_authorization_code(
                "client_id",
                "redirect_uri",
                &pkce_verifier,
                "read:documents",
            )
            .unwrap();

        // Attempt to exchange the code for tokens
        let token_response =
            auth_code_flow.exchange_code_for_token(&auth_code.code, &pkce_verifier);

        // Print the error if it exists for debugging
        if let Err(ref err) = token_response {
            eprintln!("Error occurred: {:?}", err);
        }

        assert!(
            token_response.is_ok(),
            "Expected Ok response, but got an error."
        );

        // Uncomment these lines if the token_response is OK
        // let token_response = token_response.unwrap();
        // assert_eq!(token_response.access_token, "mock_access_token");
        // assert_eq!(token_response.refresh_token, "mock_refresh_token");
    }

    // Test for expired authorization code
    #[test]
    fn test_exchange_expired_code() {
        use rand::{distributions::Alphanumeric, Rng};
        use std::sync::Arc;

        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];

        // Create an in-memory token store
        let token_store = Arc::new(InMemoryTokenStore::new());
        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        let token_generator = Arc::new(JwtTokenGenerator {
            private_key: vec![], // Use your actual private key here
            public_key: vec![],
            issuer: "test-issuer".to_string(),
            access_token_lifetime: Duration::from_secs(3600),
            refresh_token_lifetime: Duration::from_secs(86400),
            token_store: token_store.clone(), // Use token_store here instead of revoked_tokens
        });

        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime: Duration::from_secs(1), // Short lifetime
            allowed_scopes,
        };

        // Generate a valid PKCE verifier
        let pkce_verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50)
            .map(char::from)
            .collect();

        // Generate an authorization code
        let auth_code = auth_code_flow
            .generate_authorization_code(
                "client_id",
                "redirect_uri",
                &pkce_verifier,
                "read:documents",
            )
            .unwrap();

        // Wait for the code to expire
        std::thread::sleep(Duration::from_secs(2));

        // Try exchanging the expired code
        let token_response =
            auth_code_flow.exchange_code_for_token(&auth_code.code, &pkce_verifier);

        if let Err(ref err) = token_response {
            eprintln!("Error occurred: {:?}", err);
        }

        // Assert that the response is an error due to expired code
        assert!(
            token_response.is_err(),
            "Expected an error response for expired code."
        );
        assert_eq!(token_response.unwrap_err(), TokenError::InvalidGrant);
    }

    // Test for invalid PKCE verifier

    #[test]
    fn test_invalid_pkce_verifier() {
        use rand::{distributions::Alphanumeric, Rng};
        use std::sync::Arc;

        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];

        // Create an in-memory token store
        let token_store = Arc::new(InMemoryTokenStore::new());
        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        let token_generator = Arc::new(JwtTokenGenerator {
            private_key: vec![], // Use your actual private key here
            public_key: vec![],
            issuer: "test-issuer".to_string(),
            access_token_lifetime: Duration::from_secs(3600),
            refresh_token_lifetime: Duration::from_secs(86400),
            token_store: token_store.clone(), // Use token_store here
        });

        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        // Generate a valid PKCE verifier
        let pkce_verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50)
            .map(char::from)
            .collect();

        // Generate an authorization code with the valid verifier
        let auth_code = auth_code_flow
            .generate_authorization_code(
                "client_id",
                "redirect_uri",
                &pkce_verifier,
                "read:documents",
            )
            .unwrap();

        // Use an invalid PKCE verifier (e.g., too short)
        let invalid_pkce_verifier = "short_verifier";

        // Try exchanging with the invalid PKCE verifier
        let token_response =
            auth_code_flow.exchange_code_for_token(&auth_code.code, invalid_pkce_verifier);

        // Assert that the response is an error due to invalid PKCE challenge
        assert!(token_response.is_err());
        assert_eq!(
            token_response.unwrap_err(),
            TokenError::InvalidPKCEChallenge
        );
    }

    // Test for invalid authorization code
    #[test]
    fn test_invalid_authorization_code() {
        use std::sync::Arc;

        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];

        // Create an in-memory token store
        let token_store = Arc::new(InMemoryTokenStore::new());
        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        // Instantiate the JWT token generator
        let token_generator = Arc::new(JwtTokenGenerator {
            private_key: vec![], // Use your actual private key here
            public_key: vec![],
            issuer: "test-issuer".to_string(),
            access_token_lifetime: Duration::from_secs(3600),
            refresh_token_lifetime: Duration::from_secs(86400),
            token_store: token_store.clone(), // Use token_store here
        });

        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        // Try exchanging with an invalid authorization code
        let token_response =
            auth_code_flow.exchange_code_for_token("invalid_code", "pkce_challenge");

        // Assert that the response is an error
        assert!(token_response.is_err());
        assert_eq!(token_response.unwrap_err(), TokenError::InvalidGrant); // Expect an invalid grant error
    }

    /*
    "Expired Token Generation" Test
    Purpose: Ensure that the generated tokens (access and refresh) adhere to the expected expiration times and that the system correctly handles expired tokens.
    */

    #[test]
    fn test_expired_token_generation() {
        use rand::{distributions::Alphanumeric, Rng};
        use std::thread::sleep;

        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];
        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));

        // Create an instance of MockTokenGeneratorWithExpiry
        let token_generator = Arc::new(MockTokenGeneratorWithExpiry::new(
            Duration::from_secs(1), // access_token_lifetime
            Duration::from_secs(2), // refresh_token_lifetime
        )) as Arc<dyn TokenGenerator>; // Cast to Arc<dyn TokenGenerator>

        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator: token_generator.clone(), // Clone the Arc here
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        // Generate a valid PKCE verifier
        let pkce_verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50)
            .map(char::from)
            .collect();

        let auth_code = auth_code_flow
            .generate_authorization_code(
                "client_id",
                "redirect_uri",
                &pkce_verifier,
                "read:documents",
            )
            .unwrap();

        // Exchange the code for tokens
        let token_response = auth_code_flow
            .exchange_code_for_token(&auth_code.code, &pkce_verifier)
            .unwrap();

        // Wait for the access token to expire
        sleep(Duration::from_secs(2));

        // Attempt to validate the access token
        let validation_result = token_generator.validate_token(
            &token_response.access_token,
            None,
            &auth_code.code,
            "read:documents",
        );

        assert!(
            validation_result.is_err(),
            "Expected token validation to fail due to expiration."
        );
        assert_eq!(validation_result.unwrap_err(), TokenError::InvalidToken);
    }

    /*
    Reuse Authorization Code
    Purpose: Ensure that an authorization code cannot be used more than once.
    */

    #[test]
    fn test_reuse_authorization_code() {
        use rand::{distributions::Alphanumeric, Rng};
        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];

        // Initialize code_store and token_generator

        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        let token_generator = Arc::new(MockTokenGenerator);

        // Creat auth_code_flow
        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        // Generate a valid PKCE verifier
        let pkce_verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50)
            .map(char::from)
            .collect();

        // Generate an authorization code
        let auth_code = auth_code_flow
            .generate_authorization_code(
                "client_id",
                "redirect_uri",
                &pkce_verifier,
                "read:documents",
            )
            .unwrap();

        // First exchange should succeed
        let first_response =
            auth_code_flow.exchange_code_for_token(&auth_code.code, &pkce_verifier);
        // eprintln!("Revoke result: {:?}", code_revoke_result);

        assert!(first_response.is_ok(), "First exchange should succeed");

        // Second exchange should fail
        let second_response =
            auth_code_flow.exchange_code_for_token(&auth_code.code, &pkce_verifier);
        assert!(
            second_response.is_err(),
            "Second exchange should fail due to resused authorizzation code"
        );
        assert_eq!(second_response.unwrap_err(), TokenError::InvalidGrant);
    }

    /*
    Invalid Scope
    Purpose: Ensure that requesting an unauthorized scope results in an error.
    */

    #[test]
    fn test_invalid_scope_request() {
        use rand::{distributions::Alphanumeric, Rng};

        //Setiup code

        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        let token_generator = Arc::new(MockTokenGenerator);

        // Define allowed scopes
        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];

        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        // Generate a valid PKCE verifier
        let pkce_verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50) // Length between 43 and 128
            .map(char::from)
            .collect();

        // Attempt to generate an authorization code with an invalid scope
        let result = auth_code_flow.generate_authorization_code(
            "client_id",
            "redirect_uri",
            &pkce_verifier,
            "invalid_scope",
        );

        assert!(result.is_err(), "Expected error due to invalid scope.");
        assert_eq!(result.unwrap_err(), AuthorizationError::InvalidScope);
    }

    /*
    Malformed PKCE Verifier
    Purpose: Ensure that a PKCE verifier with invalid characters or incorrect formatting is rejected.
    */

    #[test]
    fn test_malformed_pkce_verifier() {
        use rand::{distributions::Alphanumeric, Rng};
        // ... setup code ...
        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];
        // Initialize code_store and token_generator
        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        let token_generator = Arc::new(MockTokenGenerator);

        // Create auth_code_flow
        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store,
            token_generator,
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        // Use a PKCE verifier with invalid characters
        let invalid_verifier = "invalid_verifier!@#";

        // Attempt to generate an authorization code with the invalid PKCE verifier
        let result = auth_code_flow.generate_authorization_code(
            "client_id",
            "redirect_uri",
            &invalid_verifier, // Use invalid_verifier here
            "read:documents",
        );

        // The generation should fail due to the invalid verifier
        assert!(
            result.is_err(),
            "Expected error due to invalid PKCE verifier."
        );
        assert_eq!(result.unwrap_err(), AuthorizationError::InvalidPKCE);
    }

    /*
    Revoked Tokens
    Purpose: Ensure that revoked tokens are invalidated and cannot be used.
    */
    #[test]
    fn test_revoked_tokens() {
        use rand::{distributions::Alphanumeric, Rng};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        // Setup: Define allowed scopes, code store, and token store
        let allowed_scopes = vec!["read:documents".to_string(), "write:files".to_string()];

        let code_store = Arc::new(Mutex::new(MemoryCodeStore::new()));
        let token_store = Arc::new(MemoryTokenStoreTrait::new());
        let token_generator = Arc::new(MockTokenGenerator::default());

        // Create AuthorizationCodeFlow instance
        let mut auth_code_flow = AuthorizationCodeFlow {
            code_store: code_store.clone(),
            token_generator,
            code_lifetime: Duration::from_secs(300),
            allowed_scopes,
        };

        // Generate a valid PKCE verifier
        let pkce_verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50)
            .map(char::from)
            .collect();

        // Step 1: Generate an authorization code
        let auth_code = auth_code_flow
            .generate_authorization_code(
                "client_id",
                "redirect_uri",
                &pkce_verifier,
                "read:documents",
            )
            .unwrap();

        // Step 2: Exchange the authorization code for tokens
        let token_response = auth_code_flow
            .exchange_code_for_token(&auth_code.code, &pkce_verifier)
            .expect("Failed to exchange code for tokens.");

        // Step 3: Revoke the authorization code
        {
            let mut code_store = code_store.lock().unwrap(); // Lock the mutex to access the CodeStore
            code_store.revoke_code(&auth_code.code);
        }

        // Check if the code is revoked
        {
            let code_store = code_store.lock().unwrap(); // Lock the mutex to access the CodeStore
            assert!(
                code_store.is_code_revoked(&auth_code.code),
                "Code should be revoked."
            );
        }

        // Step 4: Attempt to exchange the revoked code, which should fail
        let second_token_response =
            auth_code_flow.exchange_code_for_token(&auth_code.code, &pkce_verifier);
        assert!(
            second_token_response.is_err(),
            "Expected error when exchanging a revoked code."
        );
        assert_eq!(second_token_response.unwrap_err(), TokenError::InvalidGrant);
    }
}
