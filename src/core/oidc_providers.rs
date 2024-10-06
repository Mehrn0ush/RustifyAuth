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
