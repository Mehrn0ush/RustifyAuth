use crate::core::types::RegistrationError;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,        // subject (user id)
    roles: Vec<String>, // roles assigned to the user
    exp: usize,         // expiration
}

pub struct RBAC {
    roles: HashMap<String, Vec<String>>, // Stores roles and associated permissions
    jwt_secret: String,
}

impl RBAC {
    pub fn new(jwt_secret: String) -> Self {
        Self {
            roles: HashMap::new(),
            jwt_secret,
        }
    }

    // Adds a new role with permissions
    pub fn add_role(&mut self, role: &str, permissions: Vec<String>) {
        self.roles.insert(role.to_string(), permissions);
    }

    // Decodes the JWT and verifies roles/permissions dynamically
    pub fn verify_permission(
        &self,
        token: &str,
        required_permission: &str,
    ) -> Result<(), RegistrationError> {
        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|_| RegistrationError::UnauthorizedClient)?;

        let user_roles = decoded.claims.roles;
        for role in user_roles {
            if let Some(permissions) = self.roles.get(&role) {
                if permissions.contains(&required_permission.to_string()) {
                    return Ok(());
                }
            }
        }

        Err(RegistrationError::UnauthorizedClient)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[test]
    fn test_rbac_verify_permission_success() {
        let mut rbac = RBAC::new("test_secret".to_string());
        rbac.add_role("admin", vec!["create".to_string(), "delete".to_string()]);

        // Create a test JWT token with admin role
        let claims = Claims {
            sub: "user1".to_string(),
            roles: vec!["admin".to_string()],
            exp: 9999999999, // Example future expiration
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test_secret"),
        )
        .unwrap();

        assert!(rbac.verify_permission(&token, "create").is_ok());
    }

    #[test]
    fn test_rbac_verify_permission_fail() {
        let mut rbac = RBAC::new("test_secret".to_string());
        rbac.add_role("user", vec!["read".to_string()]);

        // Create a test JWT token with user role
        let claims = Claims {
            sub: "user2".to_string(),
            roles: vec!["user".to_string()],
            exp: 9999999999,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test_secret"),
        )
        .unwrap();

        assert!(rbac.verify_permission(&token, "delete").is_err());
    }

    #[test]
    fn test_rbac_verify_permission_invalid_token() {
        let rbac = RBAC::new("test_secret".to_string());

        // Use an invalid JWT token
        let invalid_token = "invalid.token.here";
        assert!(rbac.verify_permission(&invalid_token, "create").is_err());
    }
}
