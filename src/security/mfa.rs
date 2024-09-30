use crate::core::authorization::AuthorizationError;
use crate::security::rate_limit::RateLimiter;
use otpauth::TOTP;
use rand::{distributions::Alphanumeric, Rng};
use std::sync::Arc;

// Assuming you have some AuthenticationService that handles password validation.
pub struct AuthenticationService;

impl AuthenticationService {
    pub fn validate_password(&self, username: &str, password: &str) -> bool {
        // Your password validation logic here
        // Return true if the password is correct, false otherwise
        true
    }
}

pub struct TotpService {
    secret: String,
    rate_limiter: Arc<RateLimiter>,
}

impl TotpService {
    // Manually generate a new TOTP secret for the user during registration
    pub fn new_secret(rate_limiter: Arc<RateLimiter>) -> Self {
        let secret: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        println!("TOTP Secret: {}", secret); // Save or display this for the user to scan
        TotpService {
            secret,
            rate_limiter,
        }
    }

    // Manually create a URL for the QR code that Google Authenticator can scan
    pub fn generate_qr_url(&self, username: &str) -> String {
        format!(
            "otpauth://totp/{app}:{user}?secret={secret}&issuer={app}",
            app = "rustify-auth",
            user = username,
            secret = self.secret
        )
    }

    // Validate the TOTP code the user provides, using rate limiting
    pub fn validate_totp_code(
        &self,
        user_id: &str,
        code: &str,
    ) -> Result<bool, AuthorizationError> {
        // Use the rate limiter to prevent brute force attacks
        if self.rate_limiter.is_rate_limited(user_id) {
            return Err(AuthorizationError::RateLimited); // Assuming `RateLimited` is a variant of `AuthorizationError`
        }

        // Parse the provided TOTP code (string) into a u32
        let parsed_code = code
            .parse::<u32>()
            .map_err(|_| AuthorizationError::InvalidTotpCode)?;

        let totp = TOTP::from_base32(&self.secret).unwrap(); // Create TOTP from the secret

        // Get the current timestamp in seconds since the epoch
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // The period for TOTP, typically 30 seconds (could be different depending on your configuration)
        let period: u64 = 30;

        // Verify the TOTP code with the parsed code, period, and current timestamp
        if totp.verify(parsed_code, period, current_timestamp) {
            Ok(true)
        } else {
            // Increment the rate limiter after a failed attempt
            self.rate_limiter.increment(user_id);
            Ok(false)
        }
    }
}

// The authorize_user function will now handle TOTP validation during login
pub fn authorize_user(
    auth_service: &AuthenticationService, // Passing the auth service as a parameter
    totp_service: &TotpService,
    username: &str,
    password: &str,
    totp_code: &str,
) -> Result<(), AuthorizationError> {
    // Validate username and password (using your existing logic)
    if !auth_service.validate_password(username, password) {
        return Err(AuthorizationError::InvalidGrant); // Use an appropriate error variant
    }

    // Validate the TOTP code
    if !totp_service.validate_totp_code(username, totp_code)? {
        return Err(AuthorizationError::InvalidTotpCode); // Use an appropriate error variant
    }

    Ok(())
}

// Sample User struct with TOTP secret
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub totp_secret: Option<String>, // Optional field if TOTP is enabled for the user
}
