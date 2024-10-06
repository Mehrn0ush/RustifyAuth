use crate::auth::mock::{MockSessionManager, MockUserAuthenticator};
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;

/// Struct representing the JWT claims.
/// Adjust the fields based on your actual JWT structure.
#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (user identifier)
    pub exp: i64,           // Expiration time as UNIX timestamp
    pub roles: Vec<String>, // Roles assigned to the user
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

pub fn rbac_check(token: &str, required_role: &str) -> RbacResult<()> {
    // Retrieve the JWT secret from environment variables
    let secret = env::var("JWT_SECRET").map_err(|_| RbacError::MissingJwtSecret)?;
    println!("Using JWT_SECRET: {}", secret); // Log the secret

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
    )
    .map_err(|err| match *err.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => RbacError::ExpiredToken,
        _ => RbacError::InvalidToken,
    })?;

    println!("Decoded token claims: {:?}", token_data.claims); // Log claims

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
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::env;

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

    #[test]
    fn test_rbac_check_expired_token() {
        dotenv::dotenv().ok();

        // Ensure JWT_SECRET is set in the environment
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");

        // Set the expiration time to a timestamp in the past
        let past_timestamp = (chrono::Utc::now() - chrono::Duration::seconds(3600)).timestamp();

        // Create claims for the test token
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: past_timestamp, // Expired token
            roles: vec!["admin".to_string()],
        };

        // Generate a test token using the JWT_SECRET
        let token = generate_test_token(claims, &jwt_secret);

        // Perform the RBAC check
        let result = rbac_check(&token, "admin");

        // Assert that the token is marked as expired
        assert!(
            matches!(result, Err(RbacError::ExpiredToken)),
            "Expected ExpiredToken, but got: {:?}",
            result
        );
    }
    #[test]
    fn test_rbac_check_missing_role() {
        dotenv::dotenv().ok(); // Load environment variables from .env

        // Ensure JWT_SECRET is set in the environment
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");

        // Define the claims with the role "user" and a valid future expiration time
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 9999999999,                 // Future expiration time
            roles: vec!["user".to_string()], // Only 'user' role
        };

        // Generate the test JWT token using the JWT_SECRET
        let token = generate_test_token(claims, &jwt_secret);

        // Run the RBAC check for the "admin" role
        let result = rbac_check(&token, "admin");

        // Debugging output to track the result
        println!("RBAC check result: {:?}", result);

        // Ensure that the result matches the expected InsufficientRole error
        assert!(
            matches!(result, Err(RbacError::InsufficientRole)),
            "Expected InsufficientRole, but got: {:?}",
            result
        );
    }

    #[test]
    fn test_rbac_check_success() {
        dotenv::dotenv().ok(); // Load environment variables from .env

        // Retrieve the JWT_SECRET from the environment
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");

        println!("JWT Secret being used: {}", jwt_secret);

        // Create claims with "admin" and "user" roles and a valid future expiration time
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 9999999999, // Future expiration time
            roles: vec!["admin".to_string(), "user".to_string()],
        };

        // Generate the test JWT token using the same secret
        let token = generate_test_token(claims, &jwt_secret);

        println!("Generated Token: {}", token);

        // Perform the RBAC check for the "admin" role
        let result = rbac_check(&token, "admin");

        println!("RBAC Check Result: {:?}", result);

        // Ensure the result is Ok, meaning the role was validated successfully
        assert!(result.is_ok(), "Expected Ok, but got: {:?}", result);
    }

    #[test]
    fn test_extract_roles_success() {
        dotenv::dotenv().ok(); // Ensure .env is loaded for consistency

        // Ensure JWT_SECRET is set in the environment
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");

        // Define the claims
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 9999999999,
            roles: vec!["admin".to_string(), "user".to_string()],
        };

        // Generate the test token using the JWT_SECRET from environment
        let token = generate_test_token(claims, &jwt_secret);

        // Log the generated token for debugging
        println!("Generated token: {}", token);

        // Extract roles
        let result = extract_roles(&token);

        // Log the result for debugging
        println!("Extract roles result: {:?}", result);

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
