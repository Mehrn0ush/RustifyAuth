use crate::authentication::{SessionManager, UserAuthenticator};
use crate::core::authorization::AuthorizationCodeFlow;
use crate::core::scopes::ScopeValidator;
use crate::core::token::TokenGenerator;
use crate::security::csrf::{validate_state, CsrfStore};
use crate::security::pkce::validate_pkce;
use crate::storage::client::{Client, ClientRepository};
use crate::storage::CodeStore;
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

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
    client_repo: web::Data<Arc<dyn ClientRepository>>,
    scope_validator: web::Data<Arc<ScopeValidator>>,
    csrf_store: web::Data<Arc<CsrfStore>>,
    code_store: web::Data<Arc<Mutex<dyn CodeStore>>>,
    token_generator: web::Data<Arc<dyn TokenGenerator>>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    let allowed_scopes = vec!["read".to_string(), "write".to_string()];

    // Step 1: Validate the client information
    let client = match client_repo.get_client(&query.client_id) {
        Some(client) => client,
        None => return Ok(HttpResponse::BadRequest().body("Invalid client_id")),
    };

    // Step 2: Handle PKCE if provided (Optional for clients supporting PKCE)
    if let (Some(code_challenge), Some(code_challenge_method)) =
        (&query.code_challenge, &query.code_challenge_method)
    {
        if !validate_pkce(
            &Some(code_challenge.clone()),
            &Some(code_challenge_method.clone()),
            &code_challenge,
        ) {
            return Ok(HttpResponse::BadRequest().body("Invalid PKCE parameters"));
        }
    }

    // Step 3: Validate CSRF state (state parameter)
    if let Some(state) = &query.state {
        let csrf_token = req
            .headers()
            .get("X-CSRF-Token")
            .and_then(|v| v.to_str().ok());
        if csrf_token.is_none() || !validate_state(&csrf_store, csrf_token.unwrap(), state) {
            return Ok(HttpResponse::BadRequest().body("Invalid CSRF state"));
        }
    }

    // Step 4: Check if the user is authenticated via session
    let session_cookie = req.cookie("session_id");
    let user = if let Some(cookie) = session_cookie {
        match session_manager.get_user_by_session(cookie.value()).await {
            Ok(user) => user, // Directly retrieve user
            Err(_) => return Ok(HttpResponse::Unauthorized().body("User not authenticated")),
        }
    } else {
        return Ok(HttpResponse::Unauthorized().body("Session cookie missing"));
    };

    // Step 5: Validate the requested scope
    if let Some(scope) = &query.scope {
        if !scope_validator.validate(&query.client_id, scope).await {
            return Ok(HttpResponse::BadRequest().body("Invalid or unauthorized scope"));
        }
    }

    // Step 6: Generate an authorization code
    let authorization_code_flow = AuthorizationCodeFlow::new(
        Arc::clone(&code_store), // Pass the Arc directly
        Arc::clone(&token_generator),
        Duration::from_secs(600), // Example lifetime
        allowed_scopes.clone(),
    );

    let authorization_code = match authorization_code_flow.generate_authorization_code(
        &client.client_id,
        &query.redirect_uri,
        &user.id,
        query
            .scope
            .clone()
            .unwrap_or_else(|| "".to_string())
            .as_str(),
    ) {
        Ok(code) => code,
        Err(_) => {
            return Ok(
                HttpResponse::InternalServerError().body("Failed to generate authorization code")
            )
        }
    };

    // Step 7: Redirect to the client's redirect URI with the authorization code
    let redirect_url = format!(
        "{}?code={}&state={}",
        query.redirect_uri,
        authorization_code.code,
        query.state.clone().unwrap_or_else(|| "".to_string())
    );

    Ok(HttpResponse::Found()
        .header("Location", redirect_url)
        .finish())
}
