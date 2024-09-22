use crate::authentication::{SessionManager, UserAuthenticator};
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

pub async fn authorize<A: UserAuthenticator, S: SessionManager>(
    query: web::Query<AuthorizationRequest>,
    authenticator: web::Data<Arc<A>>,
    session_manager: web::Data<Arc<S>>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Validate the client information
    if !is_valid_client(&query.client_id) {
        return Ok(HttpResponse::BadRequest().body("Invalid client_id"));
    }

    // Handle PKCE if provided
    if query.code_challenge.is_some() && query.code_challenge_method.is_some() {
        if !validate_pkce(&query.code_challenge, &query.code_challenge_method) {
            return Ok(HttpResponse::BadRequest().body("Invalid PKCE parameters"));
        }
    }

    // State parameter to prevent CSRF
    if let Some(state) = &query.state {
        save_state(state);
    }

    // Redirect to login if the user is not authenticated
    if !is_authenticated() {
        return Ok(HttpResponse::Found().header("Location", "/login").finish());
    }

    // Validate the requested scope
    if !validate_scopes(&query.client_id, &query.scope) {
        return Ok(HttpResponse::BadRequest().body("Invalid scope"));
    }

    // Authorization successful
    Ok(HttpResponse::Ok().body("Authorization successful"))
}

fn is_valid_client(client_id: &str) -> bool {
    true // Replace with real client validation logic
}

fn validate_pkce(code_challenge: &Option<String>, code_challenge_method: &Option<String>) -> bool {
    match code_challenge_method.as_deref() {
        Some("S256") => true,
        Some("plain") => true,
        _ => false,
    }
}

fn save_state(state: &str) {
    println!("Saving state: {}", state);
}

fn validate_state(state: &str) -> bool {
    true // Replace with real state validation logic
}

fn is_authenticated() -> bool {
    false // Placeholder for real authentication logic
}

fn validate_scopes(client_id: &str, scope: &Option<String>) -> bool {
    true // Replace with real scope validation logic
}
