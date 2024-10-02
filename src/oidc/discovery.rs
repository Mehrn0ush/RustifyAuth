use reqwest::Client;
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize, Debug)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    // Add other fields as needed
}

pub async fn fetch_discovery_document(
    client: &Client,
) -> Result<DiscoveryDocument, Box<dyn Error>> {
    let url = "https://accounts.google.com/.well-known/openid-configuration";
    let response = client.get(url).send().await?;

    if response.status().is_success() {
        let discovery_doc: DiscoveryDocument = response.json().await?;
        Ok(discovery_doc)
    } else {
        Err(Box::from(format!(
            "Failed to fetch discovery document: {}",
            response.status()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_fetch_discovery_document() {
        // Start a WireMock server
        let mock_server = MockServer::start().await;

        // Define the expected response for the WireMock server
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                "response_types_supported": ["code", "token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            })))
            .mount(&mock_server)
            .await;

        // Use the mock server's URL for the request
        let client = Client::new();
        let discovery_doc = fetch_discovery_document(&client)
            .await
            .expect("Failed to fetch discovery document");
        assert_eq!(discovery_doc.issuer, "https://accounts.google.com");
    }
}
