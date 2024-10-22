use crate::core::types::{TokenError, TokenResponse};
use std::collections::HashMap;

// Define the trait for handling extension grants
pub trait ExtensionGrantHandler {
    fn handle_extension_grant(
        &self,
        grant_type: &str,
        params: &std::collections::HashMap<String, String>,
    ) -> Result<TokenResponse, TokenError>;
}

// Implement a custom grant handler
pub struct CustomGrant;

impl ExtensionGrantHandler for CustomGrant {
    fn handle_extension_grant(
        &self,
        grant_type: &str,
        params: &std::collections::HashMap<String, String>,
    ) -> Result<TokenResponse, TokenError> {
        if grant_type == "urn:ietf:params:oauth:grant-type:custom-grant" {
            // Add custom logic here
            println!("Handling custom grant type");

            // Validate required parameters from `params`

            // Return a token response after verifying params
            Ok(TokenResponse {
                access_token: "custom_access_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 3600,
                refresh_token: "custom_refresh_token".to_string(), // Corrected type
                scope: None, // Assuming no scope is passed, update if necessary
            })
        } else {
            Err(TokenError::UnsupportedGrantType)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_custom_grant_success() {
        let grant_handler = CustomGrant;

        // Define a HashMap with expected parameters
        let mut params = HashMap::new();
        params.insert("some_param".to_string(), "value".to_string());

        // Call the handle_extension_grant function with the correct grant type
        let result = grant_handler
            .handle_extension_grant("urn:ietf:params:oauth:grant-type:custom-grant", &params);

        // Ensure the result is OK and contains expected token data
        assert!(result.is_ok());

        // Unwrap the result to get the TokenResponse
        let token_response = result.unwrap();

        // Check that the token response contains the expected values
        assert_eq!(token_response.access_token, "custom_access_token");
        assert_eq!(token_response.token_type, "Bearer");
        assert_eq!(token_response.expires_in, 3600);
        assert_eq!(token_response.refresh_token, "custom_refresh_token");
        assert!(token_response.scope.is_none()); // Expecting no scope
    }

    #[test]
    fn test_custom_grant_unsupported_grant_type() {
        let grant_handler = CustomGrant;

        // Define a HashMap with expected parameters
        let mut params = HashMap::new();
        params.insert("some_param".to_string(), "value".to_string());

        // Call the handle_extension_grant function with an unsupported grant type
        let result = grant_handler.handle_extension_grant("unsupported-grant", &params);

        // Ensure the result is an Err with TokenError::UnsupportedGrantType
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TokenError::UnsupportedGrantType);
    }

    #[test]
    fn test_custom_grant_missing_params() {
        let grant_handler = CustomGrant;

        // Call the handle_extension_grant function with empty parameters
        let params = HashMap::new();
        let result = grant_handler
            .handle_extension_grant("urn:ietf:params:oauth:grant-type:custom-grant", &params);

        // Ensure the result is OK (you can modify this to handle missing params logic)
        assert!(result.is_ok());

        // Unwrap the result to check token response
        let token_response = result.unwrap();

        // Check that the token response contains the expected values
        assert_eq!(token_response.access_token, "custom_access_token");
        assert_eq!(token_response.token_type, "Bearer");
        assert_eq!(token_response.expires_in, 3600);
        assert_eq!(token_response.refresh_token, "custom_refresh_token");
        assert!(token_response.scope.is_none());
    }
}
