use actix_web::body::BoxBody;
use actix_web::{http::StatusCode, test, web, App}; // Importing StatusCode from actix_web
use rustify_auth::core::oidc_providers::OIDCProviderConfig; // Importing OIDCProviderConfig
use rustify_auth::endpoints::{google_callback_handler, google_login_handler};
use serde_json::{json, Value};
use std::env;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[actix_web::test]
async fn test_google_login_redirect() {
    // Set mock environment variables
    env::set_var("GOOGLE_CLIENT_ID", "mock_google_client_id");
    env::set_var("GOOGLE_CLIENT_SECRET", "mock_google_client_secret");
    env::set_var(
        "GOOGLE_REDIRECT_URI",
        "http://localhost:8080/auth/google/callback",
    );

    // Print the environment variable to verify
    println!(
        "GOOGLE_REDIRECT_URI: {:?}",
        env::var("GOOGLE_REDIRECT_URI").unwrap()
    );

    // Initialize the app with the login handler route
    let app =
        test::init_service(App::new().route("/auth/google", web::get().to(google_login_handler)))
            .await;

    // Simulate a request to the Google login endpoint
    let req = test::TestRequest::get().uri("/auth/google").to_request();

    // Call the service and check if it returns a redirection
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_redirection());
}

#[actix_web::test]
async fn test_google_callback_mocked() {
    // Set mock environment variables for Google OAuth
    std::env::set_var("GOOGLE_CLIENT_ID", "mock_google_client_id");
    std::env::set_var("GOOGLE_CLIENT_SECRET", "mock_google_client_secret");
    std::env::set_var(
        "GOOGLE_REDIRECT_URI",
        "http://localhost:8080/auth/google/callback",
    );

    // Start a mock server to simulate Google OAuth endpoints
    let mock_server = MockServer::start().await;

    // Mock the OIDC discovery document endpoint
    Mock::given(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token_endpoint": format!("{}/token", mock_server.uri())
        })))
        .mount(&mock_server)
        .await;

    // Mock the Google OAuth token exchange endpoint with a JSON error response
    Mock::given(path("/token"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "The OAuth client was not found."
        })))
        .mount(&mock_server)
        .await;

    // Create a test OIDCProviderConfig pointing to the mock server
    let test_config = OIDCProviderConfig {
        client_id: "mock_google_client_id".to_string(),
        client_secret: "mock_google_client_secret".to_string(),
        redirect_uri: "http://localhost:8080/auth/google/callback".to_string(),
        discovery_url: format!("{}/.well-known/openid-configuration", mock_server.uri()),
    };

    // Initialize the test app with your Google callback handler and test config
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(test_config)) // Inject the test config
            .route(
                "/auth/google/callback",
                web::get().to(google_callback_handler),
            ),
    )
    .await;

    // Simulate a request to the callback endpoint with a mock authorization code
    let req = test::TestRequest::get()
        .uri("/auth/google/callback?code=mock_auth_code")
        .to_request();

    // Call and read the response body
    let resp = test::call_service(&app, req).await;

    // Assert the response status is BadRequest (400)
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp_body = test::read_body(resp).await;

    // Log the raw response for debugging
    println!(
        "Raw response body: {:?}",
        String::from_utf8_lossy(&resp_body)
    );

    // Try to parse the response body as JSON
    if let Ok(json_resp) = serde_json::from_slice::<Value>(&resp_body) {
        // Check if the response contains an error
        if json_resp.get("error").is_some() {
            assert_eq!(json_resp["error"], "invalid_client");
            assert_eq!(
                json_resp["error_description"],
                "The OAuth client was not found."
            );
        } else {
            panic!("Expected an error, but received a successful response.");
        }
    } else {
        // If parsing as JSON fails, show raw response for debugging
        let raw_resp = String::from_utf8_lossy(&resp_body);
        panic!("Failed to parse JSON response. Raw response: {}", raw_resp);
    }
}
