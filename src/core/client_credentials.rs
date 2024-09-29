use crate::core::token::Claims;
use crate::error::OAuthError;
use crate::jwt::generate_jwt;
use crate::jwt::SigningAlgorithm;
use crate::storage::{ClientData, StorageBackend};
use rustls_pemfile::private_key;
use std::time::{Duration, SystemTime};

/// Validates client credentials by checking against storage (e.g., Redis, SQL).
///
/// `client_id` - The ID of the client trying to authenticate.
/// `client_secret` - The client's secret for authentication.
pub fn validate_client_credentials(
    client_id: &str,
    client_secret: &str,
    storage: &dyn StorageBackend, // Abstracts storage (e.g., memory, SQL, Redis)
) -> Result<ClientData, OAuthError> {
    // Fetch client data from storage, which returns a Result<Option<ClientData>, OAuthError>
    match storage.get_client_by_id(client_id) {
        Ok(Some(client_data)) => {
            // Client found, validate the client secret
            if client_data.secret == client_secret {
                Ok(client_data) // Credentials are valid, return the client data
            } else {
                Err(OAuthError::InvalidClient) // Client secret is invalid
            }
        }
        Ok(None) => {
            // Client not found in storage
            Err(OAuthError::InvalidClient)
        }
        Err(e) => {
            // Handle any storage-level errors (e.g., database connection failure)
            Err(e)
        }
    }
}

/// Structure for the token response as per OAuth 2.0.
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Issues a token based on the validated client and requested scopes.
///
/// `client` - The validated client data.
/// `scopes` - The scopes requested by the client.
///
/// Returns `TokenResponse` with the generated token or an error.
pub fn issue_token(
    client: &ClientData,
    scopes: &[&str], // Requested scopes by client
) -> Result<TokenResponse, OAuthError> {
    // Check if requested scopes are allowed for this client
    for scope in scopes {
        if !client.allowed_scopes.contains(&scope.to_string()) {
            return Err(OAuthError::InvalidScope); // Invalid scope requested
        }
    }

    // Define the token expiry (e.g., 1 hour)

    let expiry_duration = Duration::from_secs(3600); // 1 hour
    let now = SystemTime::now();
    let now_ts = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| OAuthError::InternalError(format!("Time error: {:?}", e)))?
        .as_secs(); // now_ts is u64
    let exp_ts = now_ts + expiry_duration.as_secs(); // exp_ts is u64

    // Create the `Claims` object
    let claims = Claims {
        sub: client.client_id.clone(),
        exp: exp_ts,
        iat: now_ts,
        scope: Some(scopes.join(" ")),
        aud: None,
        client_id: Some(client.client_id.clone()),
        iss: Some("your_issuer_identifier".to_string()),
    };

    // Specify the signing algorithm
    let signing_algorithm = SigningAlgorithm::RSA; // Adjust as per your implementation

    // Generate JWT
    let token = generate_jwt(claims, signing_algorithm)?;

    // Return the token response
    Ok(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: expiry_duration.as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*; // Import the module where `validate_client_credentials` is defined
    use std::collections::HashMap;

    // Define a mock storage backend for testing purposes
    struct MockStorage {
        clients: HashMap<String, ClientData>,
    }

    impl MockStorage {
        pub fn new() -> Self {
            MockStorage {
                clients: HashMap::new(),
            }
        }

        // Add a client to the mock storage
        pub fn add_client(&mut self, client: ClientData) {
            self.clients.insert(client.client_id.clone(), client);
        }
    }

    impl StorageBackend for MockStorage {
        fn get_client_by_id(&self, client_id: &str) -> Result<Option<ClientData>, OAuthError> {
            Ok(self.clients.get(client_id).cloned())
        }
    }

    // Test case: Valid client credentials
    #[test]
    fn test_valid_client_credentials() {
        let mut storage = MockStorage::new();

        // Add a client with valid credentials
        let client = ClientData {
            client_id: "valid_client".to_string(),
            secret: "valid_secret".to_string(),
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
        };
        storage.add_client(client);

        // Call the function with valid credentials
        let result = validate_client_credentials("valid_client", "valid_secret", &storage);

        // Assert that the result is Ok and contains the correct client data
        assert!(result.is_ok());
        let client_data = result.unwrap();
        assert_eq!(client_data.client_id, "valid_client");
        assert_eq!(client_data.secret, "valid_secret");
    }

    // Test case: Invalid client secret
    #[test]
    fn test_invalid_client_secret() {
        let mut storage = MockStorage::new();

        // Add a client with valid credentials
        let client = ClientData {
            client_id: "valid_client".to_string(),
            secret: "valid_secret".to_string(),
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
        };
        storage.add_client(client);

        // Call the function with an invalid secret
        let result = validate_client_credentials("valid_client", "invalid_secret", &storage);

        // Assert that the result is an error (invalid client)
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), OAuthError::InvalidClient);
    }

    // Test case: Non-existing client
    #[test]
    fn test_non_existing_client() {
        let storage = MockStorage::new(); // No clients added

        // Call the function with a non-existing client
        let result = validate_client_credentials("non_existing_client", "some_secret", &storage);

        // Assert that the result is an error (invalid client)
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), OAuthError::InvalidClient);
    }
}
