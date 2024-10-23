use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Struct representing the JWT claims.
#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (user identifier)
    pub exp: i64,           // Expiration time as UNIX timestamp
    pub roles: Vec<String>, // Roles assigned to the user
}

/// Enum representing possible RBAC errors.
#[derive(Debug)]
pub enum RbacError {
    InvalidToken,
    InsufficientRole,
    ExpiredToken,
    Other(String),
}

/// Result type alias for RBAC operations.
pub type RbacResult<T> = Result<T, RbacError>;

/// Function to perform RBAC check, taking the JWT token, required role, and JWT secret as parameters.
pub fn rbac_check(token: &str, required_role: &str, jwt_secret: &str) -> RbacResult<()> {
    // Define the validation parameters
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    // Create a HashSet of required claims
    let mut required_claims = HashSet::new();
    required_claims.insert("sub".to_string());
    validation.required_spec_claims = required_claims;

    // Decode and validate the token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &validation,
    )
    .map_err(|err| match *err.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => RbacError::ExpiredToken,
        _ => RbacError::InvalidToken,
    })?;

    // Check if the required role is present
    if token_data.claims.roles.contains(&required_role.to_string()) {
        Ok(())
    } else {
        Err(RbacError::InsufficientRole)
    }
}

/// Helper function to extract roles from a token, taking the JWT token and secret as parameters.
pub fn extract_roles(token: &str, jwt_secret: &str) -> RbacResult<Vec<String>> {
    // Define the validation parameters
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    // Create a HashSet of required claims
    let mut required_claims = HashSet::new();
    required_claims.insert("sub".to_string());
    validation.required_spec_claims = required_claims;

    // Decode and validate the token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &validation,
    )
    .map_err(|err| match *err.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => RbacError::ExpiredToken,
        // Map additional error kinds to InvalidToken
        jsonwebtoken::errors::ErrorKind::InvalidToken
        | jsonwebtoken::errors::ErrorKind::InvalidSignature
        | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
        | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
        | jsonwebtoken::errors::ErrorKind::Base64(_)
        | jsonwebtoken::errors::ErrorKind::Json(_)
        | jsonwebtoken::errors::ErrorKind::Utf8(_) => RbacError::InvalidToken,
        _ => RbacError::Other(err.to_string()),
    })?;

    Ok(token_data.claims.roles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serial_test::serial;

    #[derive(Debug, Serialize)]
    struct TestClaims {
        sub: String,
        exp: i64,
        roles: Vec<String>,
    }

    /// Helper function to generate a JWT token for testing.
    fn generate_test_token(claims: TestClaims, secret: &str) -> String {
        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
    }

    /// Test that `rbac_check` fails with an invalid token.
    #[test]
    #[serial]
    fn test_rbac_check_invalid_token() {
        let invalid_token = "invalid.token.value";
        let result = rbac_check(invalid_token, "admin", "test_secret");
        assert!(
            matches!(result, Err(RbacError::InvalidToken)),
            "Expected InvalidToken error, but got: {:?}",
            result
        );
    }

    /// Test that `extract_roles` fails with an invalid token.
    #[test]
    #[serial]
    fn test_extract_roles_invalid_token() {
        let invalid_token = "invalid.token.value";
        let result = extract_roles(invalid_token, "test_secret");
        assert!(
            matches!(result, Err(RbacError::InvalidToken)),
            "Expected InvalidToken error, but got: {:?}",
            result
        );
    }

    /// Test that `rbac_check` correctly identifies an expired token.
    #[test]
    #[serial]
    fn test_rbac_check_expired_token() {
        // Set the expiration time to a timestamp in the past
        let past_timestamp = (Utc::now() - chrono::Duration::seconds(3600)).timestamp();

        // Create claims for the test token
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: past_timestamp, // Expired token
            roles: vec!["admin".to_string()],
        };

        // Generate a test token using the JWT secret
        let token = generate_test_token(claims, "test_secret");

        // Perform the RBAC check
        let result = rbac_check(&token, "admin", "test_secret");

        // Assert that the token is marked as expired
        assert!(
            matches!(result, Err(RbacError::ExpiredToken)),
            "Expected ExpiredToken, but got: {:?}",
            result
        );
    }

    /// Test that `rbac_check` fails when the required role is missing.
    #[test]
    #[serial]
    fn test_rbac_check_missing_role() {
        // Define the claims with the role "user" and a valid future expiration time
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 9999999999,                 // Future expiration time
            roles: vec!["user".to_string()], // Only 'user' role
        };

        // Generate the test JWT token using the JWT secret
        let token = generate_test_token(claims, "test_secret");

        // Run the RBAC check for the "admin" role
        let result = rbac_check(&token, "admin", "test_secret");

        // Ensure that the result matches the expected InsufficientRole error
        assert!(
            matches!(result, Err(RbacError::InsufficientRole)),
            "Expected InsufficientRole, but got: {:?}",
            result
        );
    }

    /// Test that `rbac_check` succeeds when the required role is present.
    #[test]
    #[serial]
    fn test_rbac_check_success() {
        // Create claims with "admin" and "user" roles and a valid future expiration time
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 9999999999, // Future expiration time
            roles: vec!["admin".to_string(), "user".to_string()],
        };

        // Generate the test JWT token using the same secret
        let token = generate_test_token(claims, "test_secret");

        // Perform the RBAC check for the "admin" role
        let result = rbac_check(&token, "admin", "test_secret");

        // Ensure the result is Ok, meaning the role was validated successfully
        assert!(result.is_ok(), "Expected Ok, but got: {:?}", result);
    }

    /// Test that `extract_roles` correctly extracts roles from a valid token.
    #[test]
    fn test_extract_roles_success() {
        // Define the claims
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 9999999999,
            roles: vec!["admin".to_string(), "user".to_string()],
        };

        // Generate the test token using the same secret
        let token = generate_test_token(claims, "test_secret");

        // Extract roles
        let result = extract_roles(&token, "test_secret");

        // Assert that the result is OK
        assert!(
            result.is_ok(),
            "Expected result to be Ok, but got: {:?}",
            result
        );

        // Get roles and check if they contain the expected values
        let roles = result.unwrap();
        assert!(roles.contains(&"admin".to_string()));
        assert!(roles.contains(&"user".to_string()));
    }
}
