use crate::authentication::{AuthError, SessionManager, UserAuthenticator};
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

pub async fn authorize(
    query: web::Query<AuthorizationRequest>,
    authenticator: web::Data<Arc<dyn UserAuthenticator>>,
    session_manager: web::Data<Arc<dyn SessionManager>>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Step 1: Validate the client information
    if !is_valid_client(&query.client_id) {
        return Ok(HttpResponse::BadRequest().body("Invalid client_id"));
    }

    // Step 2: Handle PKCE if provided
    if query.code_challenge.is_some() && query.code_challenge_method.is_some() {
        if !validate_pkce(&query.code_challenge, &query.code_challenge_method) {
            return Ok(HttpResponse::BadRequest().body("Invalid PKCE parameters"));
        }
    }

    // Step 3: State parameter to prevent CSRF
    if let Some(state) = &query.state {
        save_state(state);
    }

    // Step 4: Check if the user is authenticated
    let session_cookie = req.cookie("session_id");
    let user = if let Some(cookie) = session_cookie {
        match session_manager.get_user_by_session(cookie.value()).await {
            Ok(user) => Some(user),
            Err(_) => None,
        }
    } else {
        None
    };

    // If user is not authenticated, redirect to login
    if user.is_none() {
        // Save the original request parameters to redirect back after login
        // Redirect to login endpoint
        return Ok(HttpResponse::Found().header("Location", "/login").finish());
    }

    // User is authenticated
    let user = user.unwrap();

    // Step 5: Validate the requested scope
    if !validate_scopes(&query.client_id, &query.scope) {
        return Ok(HttpResponse::BadRequest().body("Invalid scope"));
    }

    // Step 6: Generate authorization code and redirect back to client
    let authorization_code = generate_authorization_code();

    // Normally, you would save the authorization code associated with the user and client
    // and redirect back to the client's redirect_uri with the code and state.

    let redirect_uri = format!(
        "{}?code={}&state={}",
        query.redirect_uri,
        authorization_code,
        query.state.clone().unwrap_or_default()
    );

    Ok(HttpResponse::Found()
        .header("Location", redirect_uri)
        .finish())
}

// Helper functions (to be implemented)
fn is_valid_client(client_id: &str) -> bool {
    // Validate client from database or in-memory store
    true
}

fn validate_pkce(code_challenge: &Option<String>, code_challenge_method: &Option<String>) -> bool {
    // Validate PKCE according to RFC 7636
    match code_challenge_method.as_deref() {
        Some("S256") => true,  // Support S256 method
        Some("plain") => true, // Optionally support plain method
        _ => false,            // Invalid or unsupported method
    }
}

fn save_state(state: &str) {
    // Save the state in a session or database to validate it later
    println!("Saving state: {}", state);
}

fn validate_scopes(client_id: &str, scope: &Option<String>) -> bool {
    // Validate that the requested scope is allowed for the client
    true
}

fn generate_authorization_code() -> String {
    // Generate a secure random authorization code
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect()
}

/*
Notes:

The endpoint now depends on UserAuthenticator and SessionManager, passed via web::Data<Arc<A>> and web::Data<Arc<S>>.
It checks if the user is authenticated by attempting to retrieve the session ID from a cookie.
If the user is not authenticated, it redirects to a login endpoint.
After successful authentication, it generates an authorization code and redirects the user back to the client’s redirect_uri.

*/
