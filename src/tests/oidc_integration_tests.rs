use rustify_auth::endpoints::{google_login_handler, google_callback_handler};
use actix_web::{test, web, App};
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{path, method};
use serde_json::json;
use std::env;  // Import the env module to set environment variables


#[actix_web::test]
async fn test_google_login_redirect() {
    dotenv::dotenv().ok();  // Load the .env file if it exists
    env::set_var("GOOGLE_CLIENT_ID", "mock_google_client_id");
    env::set_var("GOOGLE_CLIENT_SECRET", "mock_google_client_secret");
    env::set_var("GOOGLE_REDIRECT_URI", "http://localhost:8080/auth/google/callback");

    let app = test::init_service(App::new().route("/auth/google", web::get().to(google_login_handler))).await;
    let req = test::TestRequest::get().uri("/auth/google").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_redirection());
}

#[actix_web::test]
async fn test_google_callback_mocked() {
    dotenv::dotenv().ok();  // Load the .env file if it exists
    env::set_var("GOOGLE_CLIENT_ID", "mock_google_client_id");
    env::set_var("GOOGLE_CLIENT_SECRET", "mock_google_client_secret");
    env::set_var("GOOGLE_REDIRECT_URI", "http://localhost:8080/auth/google/callback");

    let mock_server = MockServer::start().await;

    Mock::given(path("/token"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock_access_token",
            "id_token": "mock_id_token",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    let app = test::init_service(App::new().route("/auth/google/callback", web::get().to(google_callback_handler))).await;
    let req = test::TestRequest::get().uri("/auth/google/callback?code=mock_auth_code").to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["access_token"], "mock_access_token");
    assert_eq!(resp["id_token"], "mock_id_token");
}
