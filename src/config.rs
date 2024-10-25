// src/config.rs
use serde::Deserialize;
use std::env;

#[derive(Deserialize, Debug)]
pub struct PostgresConfig {
    pub db_url: String,
    pub pool_size: usize,
}
pub struct OAuthConfig {
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_uri: String,
    pub storage_backend: String,
}

impl OAuthConfig {
    pub fn from_env() -> Self {
        let google_client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set");
        let google_client_secret =
            env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set");
        let google_redirect_uri =
            env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI must be set");

        OAuthConfig {
            google_client_id,
            google_client_secret,
            google_redirect_uri,
            storage_backend: std::env::var("STORAGE_BACKEND")
                .unwrap_or_else(|_| "in_memory".to_string()), // Default to in_memory
        }
    }
}
