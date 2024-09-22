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

            //Validate required parameters from `params` 

            // Return a token response, maybe after verifying params
            Ok(TokenResponse {
                access_token: "custom_access_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 3600,
                refresh_token: Some("custom_refresh_token".to_string()),
            })
        } else {
            Err(TokenError::UnsupportedGrantType)
        }
    }
}



