use crate::core::oidc_providers::{google_provider_config, OIDCProviderConfig};
use actix_web::{web, HttpResponse, Responder};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Debug)]
pub struct GoogleAuthCodeRequest {
    code: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct GoogleTokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct GoogleIdTokenClaims {
    pub sub: String, // Subject (user ID)
    pub email: String,
    pub aud: String, // Audience
    pub iss: String, // Issuer
    pub exp: i64,    // Expiration
}

#[derive(Deserialize, Debug)]
struct OIDCDiscoveryDocument {
    token_endpoint: String,
    // You can add other fields as needed
}

pub async fn google_login_handler() -> impl Responder {
    let config = google_provider_config();
    let authorization_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope=email%20openid%20profile",
        config.client_id, config.redirect_uri
    );

    HttpResponse::Found()
        .append_header(("Location", authorization_url))
        .finish()
}

pub async fn google_callback_handler(
    query: web::Query<GoogleAuthCodeRequest>,
    data: web::Data<OIDCProviderConfig>,
) -> impl Responder {
    let config = data.get_ref();
    let client = Client::new();

    // Fetch the discovery document
    let discovery_res = client
        .get(&config.discovery_url)
        .send()
        .await
        .expect("Failed to fetch discovery document");

    let discovery_doc: OIDCDiscoveryDocument = discovery_res
        .json()
        .await
        .expect("Failed to parse discovery document");

    // Use the token_endpoint from the discovery document
    let token_url = discovery_doc.token_endpoint;

    // Exchange authorization code for tokens
    let token_res = client
        .post(&token_url)
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", &query.code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", config.redirect_uri.as_str()),
        ])
        .send()
        .await;

    match token_res {
        Ok(response) => {
            let status = response.status();
            let raw_response = response
                .text()
                .await
                .expect("Failed to read response as text");
            println!("Raw response body: {}", raw_response);

            if !status.is_success() {
                // Try to parse the error response
                let error_value: Result<Value, _> = serde_json::from_str(&raw_response);
                if let Ok(error_json) = error_value {
                    return HttpResponse::BadRequest().json(error_json);
                } else {
                    return HttpResponse::BadRequest()
                        .body(format!("Error from Google OAuth: {}", raw_response));
                }
            }

            // Deserialize the response into GoogleTokenResponse
            let token_data: GoogleTokenResponse = serde_json::from_str(&raw_response)
                .expect("Failed to deserialize Google token response");

            HttpResponse::Ok().json(token_data)
        }
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed to request tokens: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::oidc_providers::OIDCProviderConfig;
    use actix_web::{http, test, web, App};
    use httpmock::MockServer;
    use serde_json::json;

    #[actix_rt::test]
    async fn test_google_callback_handler_success() {
        // Create a mock server
        let server = MockServer::start();

        // Mock the OIDC discovery document
        let _discovery_mock = server.mock(|when, then| {
            when.method("GET").path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "token_endpoint": server.url("/token"),
                "jwks_uri": server.url("/jwks")
            }));
        });

        // Mock Google token endpoint response
        let _token_mock = server.mock(|when, then| {
            when.method("POST").path("/token");
            then.status(200).json_body(json!({
                "access_token": "test_access_token",
                "id_token": "test_id_token",
                "expires_in": 3600,
                "scope": "email profile"
            }));
        });

        // Create a test config
        let test_config = OIDCProviderConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            discovery_url: server.url("/.well-known/openid-configuration"),
        };

        // Create app with handler and test config
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(test_config))
                .service(web::resource("/callback").route(web::get().to(google_callback_handler))),
        )
        .await;

        // Simulate request with a valid code
        let req = test::TestRequest::get()
            .uri("/callback?code=test_code")
            .to_request();

        // Call the service and check the response
        let resp = test::call_service(&app, req).await;

        // Assert the response status is OK (200)
        assert_eq!(resp.status(), http::StatusCode::OK);

        // Deserialize the response body
        let body = test::read_body(resp).await;
        let response: GoogleTokenResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        // Assert the correct token data is returned
        assert_eq!(response.access_token, "test_access_token");
        assert_eq!(response.id_token, "test_id_token");
    }

    #[actix_rt::test]
    async fn test_google_callback_handler_error() {
        // Create a mock server
        let server = MockServer::start();

        // Mock the OIDC discovery document
        let _discovery_mock = server.mock(|when, then| {
            when.method("GET").path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "token_endpoint": server.url("/token"),
                "jwks_uri": server.url("/jwks")
            }));
        });

        // Mock error response from Google token endpoint
        let _token_mock = server.mock(|when, then| {
            when.method("POST").path("/token");
            then.status(400)
                .json_body(json!({ "error": "invalid_grant", "error_description": "The authorization code is invalid or expired." }));
        });

        // Create a test config
        let test_config = OIDCProviderConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            discovery_url: server.url("/.well-known/openid-configuration"),
        };

        // Create app with handler and test config
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(test_config))
                .service(web::resource("/callback").route(web::get().to(google_callback_handler))),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/callback?code=invalid_code")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        // Deserialize the response body as JSON
        let body = test::read_body(resp).await;
        let error_response: serde_json::Value =
            serde_json::from_slice(&body).expect("Failed to parse error response");

        // Assert the error message is returned from Google
        assert_eq!(error_response["error"], "invalid_grant");
        assert_eq!(
            error_response["error_description"],
            "The authorization code is invalid or expired."
        );
    }

    #[actix_rt::test]
    async fn test_google_callback_mocked() {
        // Create a mock server
        let server = MockServer::start();

        // Mock the OIDC discovery document
        let _discovery_mock = server.mock(|when, then| {
            when.method("GET").path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "token_endpoint": server.url("/token"),
                "jwks_uri": server.url("/jwks")
            }));
        });

        // Mock an error response from Google token endpoint
        let _token_mock = server.mock(|when, then| {
            when.method("POST").path("/token");
            then.status(400)
                .json_body(json!({ "error": "invalid_grant", "error_description": "The authorization code is invalid or expired." }));
        });

        // Create a test config
        let test_config = OIDCProviderConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            discovery_url: server.url("/.well-known/openid-configuration"),
        };

        // Create app with handler and test config
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(test_config))
                .service(web::resource("/callback").route(web::get().to(google_callback_handler))),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/callback?code=invalid_code")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        // Deserialize the response body as JSON
        let body = test::read_body(resp).await;
        let error_response: serde_json::Value =
            serde_json::from_slice(&body).expect("Failed to parse error response");

        // Assert the error message is returned from Google
        assert_eq!(error_response["error"], "invalid_grant");
        assert_eq!(
            error_response["error_description"],
            "The authorization code is invalid or expired."
        );
    }
}
