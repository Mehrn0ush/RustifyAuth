use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Default)] // Add Default here
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: usize, // Keeping it as usize
    pub aud: String,
    pub iss: String,
}

pub fn validate_google_claims(claims: &Claims) -> Result<(), String> {
    // Validate the audience (aud) and issuer (iss)
    let expected_aud = "your_client_id.apps.googleusercontent.com"; // Replace with your Google Client ID
    let expected_iss = "https://accounts.google.com";

    if claims.aud != expected_aud {
        return Err(format!("Invalid audience: {}", claims.aud));
    }

    if claims.iss != expected_iss {
        return Err(format!("Invalid issuer: {}", claims.iss));
    }

    if claims.exp < get_current_timestamp() {
        return Err("Token has expired".to_string());
    }

    Ok(())
}

fn get_current_timestamp() -> usize {
    // Get the current timestamp in seconds
    let now = chrono::Utc::now();
    now.timestamp() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_google_claims_valid() {
        let claims = Claims {
            sub: "1234567890".to_string(),
            email: "test@example.com".to_string(),
            exp: get_current_timestamp() + 10000, // Valid expiration time
            aud: "your_client_id.apps.googleusercontent.com".to_string(), // Replace with your Google Client ID
            iss: "https://accounts.google.com".to_string(),
        };

        let result = validate_google_claims(&claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_google_claims_invalid_aud() {
        let claims = Claims {
            sub: "1234567890".to_string(),
            email: "test@example.com".to_string(),
            exp: get_current_timestamp() + 10000,
            aud: "invalid_audience".to_string(),
            iss: "https://accounts.google.com".to_string(),
        };

        let result = validate_google_claims(&claims);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid audience: invalid_audience");
    }

    #[test]
    fn test_validate_google_claims_invalid_iss() {
        let claims = Claims {
            sub: "1234567890".to_string(),
            email: "test@example.com".to_string(),
            exp: get_current_timestamp() + 10000,
            aud: "your_client_id.apps.googleusercontent.com".to_string(), // Replace with your Google Client ID
            iss: "invalid_issuer".to_string(),
        };

        let result = validate_google_claims(&claims);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid issuer: invalid_issuer");
    }

    #[test]
    fn test_validate_google_claims_expired_token() {
        let claims = Claims {
            sub: "1234567890".to_string(),
            email: "test@example.com".to_string(),
            exp: get_current_timestamp() - 1, // Expired token
            aud: "your_client_id.apps.googleusercontent.com".to_string(), // Replace with your Google Client ID
            iss: "https://accounts.google.com".to_string(),
        };

        let result = validate_google_claims(&claims);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Token has expired");
    }
}
