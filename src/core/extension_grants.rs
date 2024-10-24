use crate::core::types::{TokenError, TokenRequest, TokenResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::string::String;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

pub trait DeviceFlowHandler {
    fn generate_device_code(&self) -> DeviceCodeResponse;
    fn poll_device_code(&self, device_code: &str) -> Result<TokenResponse, TokenError>;
}

pub struct DefaultDeviceFlowHandler {
    pub verification_uri_base: String, // Configurable URI base for production
}
impl DefaultDeviceFlowHandler {
    pub fn new(verification_uri_base: &str) -> Self {
        Self {
            verification_uri_base: verification_uri_base.to_string(),
        }
    }

    // Helper function to generate a random user code
    fn generate_user_code(&self) -> String {
        // For production, use a proper random generator
        format!("{}-{}", rand::random::<u16>(), rand::random::<u16>())
    }
}

impl DeviceFlowHandler for DefaultDeviceFlowHandler {
    fn generate_device_code(&self) -> DeviceCodeResponse {
        DeviceCodeResponse {
            device_code: "generated_device_code".to_string(), // For production, generate a secure device code
            user_code: self.generate_user_code(),
            verification_uri: format!("{}/device", self.verification_uri_base),
            expires_in: 600, // 10 minutes expiration
            interval: 5,     // Polling interval of 5 seconds
        }
    }

    fn poll_device_code(&self, device_code: &str) -> Result<TokenResponse, TokenError> {
        if device_code == "valid_device_code" {
            Ok(TokenResponse {
                access_token: "device_access_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 3600,                                  // 1 hour
                refresh_token: "device_refresh_token".to_string(), // Always provide a valid refresh token as a String
                scope: Some("read write".to_string()),
            })
        } else {
            Err(TokenError::InvalidGrant)
        }
    }
}

pub trait ExtensionGrantHandler {
    fn handle_extension_grant(
        &self,
        grant_type: &str,
        params: &HashMap<String, String>,
    ) -> Result<TokenResponse, TokenError>;
}

pub struct CustomGrant;

impl ExtensionGrantHandler for CustomGrant {
    fn handle_extension_grant(
        &self,
        grant_type: &str,
        params: &HashMap<String, String>,
    ) -> Result<TokenResponse, TokenError> {
        if grant_type == "urn:ietf:params:oauth:grant-type:custom-grant" {
            // Add custom logic here, e.g., validate `params`
            println!("Handling custom grant type");

            // Return a token response
            Ok(TokenResponse {
                access_token: "custom_access_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 3600,                                  // 1 hour
                refresh_token: "custom_refresh_token".to_string(), // Provide a valid refresh token
                scope: Some("custom_scope".to_string()),
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
    fn test_generate_device_code() {
        let handler = DefaultDeviceFlowHandler::new("https://example.com");
        let response = handler.generate_device_code();

        assert_eq!(response.device_code, "generated_device_code");
        assert_eq!(response.verification_uri, "https://example.com/device");
        assert!(response.expires_in > 0);
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn test_poll_valid_device_code() {
        let handler = DefaultDeviceFlowHandler::new("https://example.com");
        let result = handler.poll_device_code("valid_device_code");

        assert!(result.is_ok());
        let token_response = result.unwrap();
        assert_eq!(token_response.access_token, "device_access_token");
        assert_eq!(token_response.token_type, "Bearer");
        assert_eq!(token_response.expires_in, 3600);
        assert_eq!(token_response.refresh_token, "device_refresh_token");
        assert_eq!(token_response.scope.unwrap(), "read write");
    }

    #[test]
    fn test_poll_invalid_device_code() {
        let handler = DefaultDeviceFlowHandler::new("https://example.com");
        let result = handler.poll_device_code("invalid_device_code");

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error, TokenError::InvalidGrant);
    }

    #[test]
    fn test_handle_custom_grant() {
        let handler = CustomGrant;
        let mut params = HashMap::new();
        params.insert("custom_param".to_string(), "value".to_string());

        let result = handler
            .handle_extension_grant("urn:ietf:params:oauth:grant-type:custom-grant", &params);
        assert!(result.is_ok());

        let token_response = result.unwrap();
        assert_eq!(token_response.access_token, "custom_access_token");
        assert_eq!(token_response.token_type, "Bearer");
        assert_eq!(token_response.expires_in, 3600);
        assert_eq!(token_response.refresh_token, "custom_refresh_token");
        assert_eq!(token_response.scope.unwrap(), "custom_scope");
    }

    #[test]
    fn test_handle_unsupported_grant() {
        let handler = CustomGrant;
        let mut params = HashMap::new();
        params.insert("unsupported_param".to_string(), "value".to_string());

        let result = handler.handle_extension_grant("unsupported_grant_type", &params);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error, TokenError::UnsupportedGrantType);
    }
}
