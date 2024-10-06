use actix_web::body::BoxBody;
use actix_web::{test, web, App};
use rustify_auth::endpoints::{google_callback_handler, google_login_handler};
use serde_json::{json, Value};
use std::env;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate}; // Import the env module to set environment variables

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

    let app =
        test::init_service(App::new().route("/auth/google", web::get().to(google_login_handler)))
            .await;
    let req = test::TestRequest::get().uri("/auth/google").to_request();
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

    // Mock the Google OAuth token exchange endpoint with a JSON error response
    Mock::given(path("/token"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "The OAuth client was not found."
        })))
        .mount(&mock_server)
        .await;

    // Initialize the test app with your Google callback handler
    let app = test::init_service(App::new().route(
        "/auth/google/callback",
        web::get().to(google_callback_handler),
    ))
    .await;

    // Simulate a request to the callback endpoint with a mock authorization code
    let req = test::TestRequest::get()
        .uri("/auth/google/callback?code=mock_auth_code")
        .to_request();

    // Call and read the response body as text first
    let resp_body = test::call_and_read_body(&app, req).await;

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
            // If it's not an error, check the token fields
            assert_eq!(json_resp["access_token"], "mock_access_token");
            assert_eq!(json_resp["id_token"], "mock_id_token");
            assert_eq!(json_resp["expires_in"], 3600);
            assert_eq!(json_resp["scope"], "email");
        }
    } else {
        // If parsing as JSON fails, handle the raw response and assert it
        let raw_resp = String::from_utf8_lossy(&resp_body);
        assert!(raw_resp.contains("Error from Google OAuth"));
        assert!(raw_resp.contains("\"error\": \"invalid_client\""));
        assert!(raw_resp.contains("\"error_description\": \"The OAuth client was not found.\""));
    }
}
