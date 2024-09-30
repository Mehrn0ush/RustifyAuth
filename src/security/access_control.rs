use crate::core::types::RegistrationError;
use std::collections::HashMap;

pub struct RBAC {
    roles: HashMap<String, Vec<String>>, // Stores roles and associated permissions
}

impl RBAC {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
        }
    }

    // Adds a new role with permissions
    pub fn add_role(&mut self, role: &str, permissions: Vec<String>) {
        self.roles.insert(role.to_string(), permissions);
    }

    // Verifies if the token (user role) has the required permission
    pub fn rbac_check(&self, token: &str, required_permission: &str) -> Result<(), RegistrationError> {
        if let Some(permissions) = self.roles.get(token) {
            if permissions.contains(&required_permission.to_string()) {
                return Ok(());
            }
        }
        Err(RegistrationError::UnauthorizedClient)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rbac_check_success() {
        let mut rbac = RBAC::new();
        rbac.add_role("admin", vec!["create".to_string(), "delete".to_string()]);
        assert!(rbac.rbac_check("admin", "create").is_ok());
    }

    #[test]
    fn test_rbac_check_fail() {
        let mut rbac = RBAC::new();
        rbac.add_role("user", vec!["read".to_string()]);
        assert!(rbac.rbac_check("user", "delete").is_err());
    }
}
