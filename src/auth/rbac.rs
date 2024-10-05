use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, TokenData};
use crate::auth::mock::{MockUserAuthenticator, MockSessionManager};
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use std::env;


/// Struct representing the JWT claims.
/// Adjust the fields based on your actual JWT structure.
#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: String,                // Subject (user identifier)
    pub exp: i64,                 // Expiration time as UNIX timestamp
    pub roles: Vec<String>,         // Roles assigned to the user
}

/// Enum representing possible RBAC errors.
#[derive(Debug)]
pub enum RbacError {
    MissingJwtSecret,
    InvalidToken,
    InsufficientRole,
    ExpiredToken,
    Other(String),
}

/// Result type alias for RBAC operations.
pub type RbacResult<T> = Result<T, RbacError>;

/// Performs a Role-Based Access Control (RBAC) check.
///
/// # Arguments
///
/// * `token` - The bearer token to validate.
/// * `required_role` - The role required to perform the action.
///
/// # Returns
///
/// * `Ok(())` if the token is valid and contains the required role.
/// * `Err(RbacError)` otherwise.
///
/// # Example
///
/// ```
/// use crate::authentication::rbac::{rbac_check, RbacError};
///
/// let token = "valid_jwt_token_here";
/// match rbac_check(token, "admin") {
///     Ok(_) => println!("Access granted"),
///     Err(e) => println!("Access denied: {:?}", e),
/// }
/// ```
pub fn rbac_check(token: &str, required_role: &str) -> RbacResult<()> {
    // Retrieve the JWT secret from environment variables
    let secret = env::var("JWT_SECRET").map_err(|_| RbacError::MissingJwtSecret)?;

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
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    ).map_err(|err| match *err.kind() {
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


/// Helper function to extract roles from a token.
/// This can be used if you need to access roles beyond RBAC checks.
pub fn extract_roles(token: &str) -> RbacResult<Vec<String>> {
    // Retrieve the JWT secret from environment variables
    let secret = env::var("JWT_SECRET").map_err(|_| RbacError::MissingJwtSecret)?;

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
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    ).map_err(|err| match *err.kind() {
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
    use jsonwebtoken::{encode, Header, EncodingKey};
    use std::env;

    #[derive(Debug, Serialize)]
    struct TestClaims {
        sub: String,
        exp: i64, // Changed to i64
        roles: Vec<String>,
    }

    /// Helper function to generate a JWT token for testing.
    fn generate_test_token(claims: TestClaims, secret: &str) -> String {
        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
    }



    #[test]
    fn test_rbac_check_invalid_token() {
        // Set the JWT_SECRET environment variable for testing
        env::set_var("JWT_SECRET", "test_secret");
    
        let invalid_token = "invalid.token.value";
    
        let result = rbac_check(invalid_token, "admin");
        assert!(matches!(result, Err(RbacError::InvalidToken)));
    
        // Clean up
        env::remove_var("JWT_SECRET");
    }


    #[test]
    fn test_extract_roles_invalid_token() {
        // Set the JWT_SECRET environment variable for testing
        env::set_var("JWT_SECRET", "test_secret");

        let invalid_token = "invalid.token.value";

        let result = extract_roles(invalid_token);
        assert!(matches!(result, Err(RbacError::InvalidToken)));

        // Clean up
        env::remove_var("JWT_SECRET");
    }
}