#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::rate_limit::RateLimiter;
    use std::time::Duration;
    use std::sync::Arc;

    #[test]
    fn test_totp_with_rate_limiting() {
        let rate_limiter = Arc::new(RateLimiter::new(3, Duration::from_secs(60))); // Allow 3 attempts in 60 seconds
        let totp_service = TotpService::new_secret(rate_limiter.clone());

        let user_id = "user123";

        // Simulate 3 failed attempts
        for _ in 0..3 {
            assert_eq!(totp_service.validate_totp_code(user_id, "wrong_code").unwrap(), false);
        }

        // The fourth attempt should be rate-limited
        assert!(totp_service.validate_totp_code(user_id, "wrong_code").is_err());
    }
}
