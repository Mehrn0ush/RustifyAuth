#[cfg(test)]
mod tests {
    use crate::core::token::{JwtTokenGenerator, Claims};
    use std::time::Duration;

    #[test]
    fn test_jwt_token_generation_and_validation() {
        let generator = JwtTokenGenerator {
            private_key: vec![/* your RSA private key bytes */],
            issuer: "test-issuer".to_string(),
            access_token_lifetime: Duration::from_secs(3600),
            refresh_token_lifetime: Duration::from_secs(86400),
        };

        let client_id = "test-client";
        let user_id = "user-123";

        // Generate token
        let token = generator.generate_access_token(client_id, user_id).unwrap();

        // Validate token
        let result = generator.validate_token(&token, None);
        assert!(result.is_ok(), "Token should be valid");

        // Validate invalid token (tampered or expired)
        let invalid_token = "invalid-token";
        let result = generator.validate_token(invalid_token, None);
        assert!(result.is_err(), "Token should be invalid");
    }
}
