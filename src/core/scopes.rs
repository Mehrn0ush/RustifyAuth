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
