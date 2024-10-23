use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct OIDCProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub discovery_url: String,
}

pub fn google_provider_config() -> OIDCProviderConfig {
    OIDCProviderConfig {
        client_id: std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"),
        client_secret: std::env::var("GOOGLE_CLIENT_SECRET")
            .expect("GOOGLE_CLIENT_SECRET must be set"),
        redirect_uri: std::env::var("GOOGLE_REDIRECT_URI")
            .expect("GOOGLE_REDIRECT_URI must be set"),
        discovery_url: "https://accounts.google.com/.well-known/openid-configuration".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    #[actix_rt::test]
    async fn test_google_provider_config_success() {
        // Set up mock environment variables
        std::env::set_var("GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("GOOGLE_CLIENT_SECRET", "test_client_secret");
        std::env::set_var("GOOGLE_REDIRECT_URI", "https://example.com/callback");

        // Call the google_provider_config function to get the config
        let config = google_provider_config();

        // Assert that the config contains the expected values
        assert_eq!(config.client_id, "test_client_id");
        assert_eq!(config.client_secret, "test_client_secret");
        assert_eq!(config.redirect_uri, "https://example.com/callback");
    }

    #[test]
    #[should_panic(expected = "GOOGLE_CLIENT_ID must be set")]
    fn test_missing_google_client_id() {
        // Unset the GOOGLE_CLIENT_ID to trigger panic
        env::remove_var("GOOGLE_CLIENT_ID");
        env::set_var("GOOGLE_CLIENT_SECRET", "test_client_secret");
        env::set_var("GOOGLE_REDIRECT_URI", "https://example.com/callback");

        // This should panic due to missing GOOGLE_CLIENT_ID
        google_provider_config();
    }

    #[test]
    #[should_panic(expected = "GOOGLE_CLIENT_SECRET must be set")]
    fn test_missing_google_client_secret() {
        // Unset the GOOGLE_CLIENT_SECRET to trigger panic
        env::set_var("GOOGLE_CLIENT_ID", "test_client_id");
        env::remove_var("GOOGLE_CLIENT_SECRET");
        env::set_var("GOOGLE_REDIRECT_URI", "https://example.com/callback");

        // This should panic due to missing GOOGLE_CLIENT_SECRET
        google_provider_config();
    }

    #[test]
    #[should_panic(expected = "GOOGLE_REDIRECT_URI must be set")]
    fn test_missing_google_redirect_uri() {
        // Unset the GOOGLE_REDIRECT_URI to trigger panic
        env::set_var("GOOGLE_CLIENT_ID", "test_client_id");
        env::set_var("GOOGLE_CLIENT_SECRET", "test_client_secret");
        env::remove_var("GOOGLE_REDIRECT_URI");

        // This should panic due to missing GOOGLE_REDIRECT_URI
        google_provider_config();
    }
}
