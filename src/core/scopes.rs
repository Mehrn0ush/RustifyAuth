use crate::core::types::TokenError;
use std::collections::HashSet;

pub struct ScopeValidator {
    allowed_scopes: HashSet<String>,
}

impl ScopeValidator {
    pub fn new(scopes: Vec<String>) -> Self {
        let allowed_scopes: HashSet<String> = scopes.into_iter().collect();
        ScopeValidator { allowed_scopes }
    }

    // Validate if the requested scope is allowed for the given client
    pub async fn validate(&self, client_id: &str, requested_scope: &str) -> bool {
        let requested_scopes: HashSet<String> = requested_scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Check if all requested scopes are allowed
        requested_scopes.is_subset(&self.allowed_scopes)
    }

    // Optionally, you can add methods to manage scopes (e.g., add/remove)
}

use super::*;

#[tokio::test]
async fn test_scope_validator_all_scopes_allowed() {
    // Arrange: Create a ScopeValidator with allowed scopes
    let allowed_scopes = vec![
        "read".to_string(),
        "write".to_string(),
        "delete".to_string(),
    ];
    let validator = ScopeValidator::new(allowed_scopes);

    // Act: Validate a request with a valid scope
    let client_id = "client_123";
    let requested_scope = "read write";
    let result = validator.validate(client_id, requested_scope).await;

    // Assert: The requested scopes should be valid
    assert!(result);
}

#[tokio::test]
async fn test_scope_validator_some_scopes_invalid() {
    // Arrange: Create a ScopeValidator with allowed scopes
    let allowed_scopes = vec!["read".to_string(), "write".to_string()];
    let validator = ScopeValidator::new(allowed_scopes);

    // Act: Validate a request with an invalid scope
    let client_id = "client_123";
    let requested_scope = "read write delete";
    let result = validator.validate(client_id, requested_scope).await;

    // Assert: The requested scopes should be invalid
    assert!(!result);
}

#[tokio::test]
async fn test_scope_validator_no_scopes_requested() {
    // Arrange: Create a ScopeValidator with allowed scopes
    let allowed_scopes = vec!["read".to_string(), "write".to_string()];
    let validator = ScopeValidator::new(allowed_scopes);

    // Act: Validate a request with no scopes
    let client_id = "client_123";
    let requested_scope = "";
    let result = validator.validate(client_id, requested_scope).await;

    // Assert: No requested scopes should be valid
    assert!(result);
}

#[tokio::test]
async fn test_scope_validator_with_disallowed_scope() {
    // Arrange: Create a ScopeValidator with allowed scopes
    let allowed_scopes = vec!["read".to_string(), "write".to_string()];
    let validator = ScopeValidator::new(allowed_scopes);

    // Act: Validate a request with a disallowed scope
    let client_id = "client_123";
    let requested_scope = "delete";
    let result = validator.validate(client_id, requested_scope).await;

    // Assert: The requested scope should be invalid
    assert!(!result);
}

#[tokio::test]
async fn test_scope_validator_all_scopes_empty() {
    // Arrange: Create a ScopeValidator with no allowed scopes
    let allowed_scopes = vec![];
    let validator = ScopeValidator::new(allowed_scopes);

    // Act: Validate a request with any scope
    let client_id = "client_123";
    let requested_scope = "read";
    let result = validator.validate(client_id, requested_scope).await;

    // Assert: The requested scope should be invalid since no scopes are allowed
    assert!(!result);
}
