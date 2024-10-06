use crate::core::oidc_providers::google_provider_config;
use actix_web::{web, HttpResponse, Responder};
use reqwest::Client;
use serde::{Deserialize, Serialize};

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

pub async fn google_callback_handler(query: web::Query<GoogleAuthCodeRequest>) -> impl Responder {
    let config = google_provider_config();
    let client = Client::new();

    // Exchange authorization code for tokens
    let token_url = "https://oauth2.googleapis.com/token";
    let token_res = client
        .post(token_url)
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", &query.code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", config.redirect_uri.as_str()),
        ])
        .send()
        .await
        .expect("Failed to request tokens");

    let raw_response = token_res
        .text()
        .await
        .expect("Failed to read response as text");
    println!("Raw response body: {}", raw_response);

    // Handle error in the response
    if raw_response.contains("error") {
        return HttpResponse::BadRequest()
            .body(format!("Error from Google OAuth: {}", raw_response));
    }

    // Deserialize the response into GoogleTokenResponse
    let token_data: GoogleTokenResponse =
        serde_json::from_str(&raw_response).expect("Failed to deserialize Google token response");

    HttpResponse::Ok().json(token_data)
}
