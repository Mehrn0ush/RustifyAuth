use crate::authentication::{AuthError, SessionManager, UserAuthenticator};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use log::{debug, error};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub async fn authorize(
    query: Result<web::Query<AuthorizationRequest>, actix_web::Error>,
    authenticator: web::Data<Arc<dyn UserAuthenticator>>,
    session_manager: web::Data<Arc<dyn SessionManager>>,
    req: HttpRequest,
) -> Result<HttpResponse, Error> {
    let query = match query {
        Ok(q) => q,
        Err(e) => {
            error!("Failed to parse query parameters: {}", e);
            return Ok(HttpResponse::BadRequest().body("Invalid query parameters"));
        }
    };

    debug!("Authorization request received: {:?}", query);
    debug!("Starting authorization process");

    // Step 1: Validate the client information
    if !is_valid_client(&query.client_id) {
        error!("Invalid client_id: {}", query.client_id);
        return Ok(HttpResponse::BadRequest().body("Invalid client_id"));
    }
    debug!("Client ID validated");

    // Step 2: Handle PKCE if provided
    if let (Some(code_challenge), Some(code_challenge_method)) =
        (&query.code_challenge, &query.code_challenge_method)
    {
        if !validate_pkce(&code_challenge, &code_challenge_method) {
            error!("Invalid PKCE parameters");
            return Ok(HttpResponse::BadRequest().body("Invalid PKCE parameters"));
        }
    }
    debug!("PKCE validation passed");

    // Step 3: Check if the user is authenticated
    let session_cookie = req.cookie("session_id");
    let user = if let Some(cookie) = session_cookie {
        debug!("Session cookie found: {}", cookie.value());

        match session_manager.get_user_by_session(cookie.value()).await {
            Ok(user) => user,
            Err(AuthError::SessionNotFound) => {
                error!("Session not found for cookie: {}", cookie.value());
                return Ok(HttpResponse::Unauthorized().body("Invalid session"));
            }
            Err(AuthError::InternalError) => {
                error!("Internal server error while retrieving session");
                return Ok(HttpResponse::InternalServerError().body("Internal server error"));
            }
            Err(e) => {
                error!("Unhandled authentication error: {:?}", e);
                return Ok(HttpResponse::InternalServerError().body("Internal server error"));
            }
        }
    } else {
        // No session cookie, redirect to login
        debug!("No session cookie found, redirecting to login");

        return Ok(HttpResponse::Found().header("Location", "/login").finish());
    };
    debug!("User authenticated: {:?}", user);

    // Step 4: Validate the requested scope
    if !validate_scopes(&query.client_id, &query.scope) {
        error!("Invalid scope for client_id: {}", query.client_id);
        return Ok(HttpResponse::BadRequest().body("Invalid scope"));
    }
    debug!("Scope validated");

    // Step 5: Generate authorization code and redirect back to client
    let authorization_code = generate_authorization_code();
    debug!("Authorization code generated: {}", authorization_code);

    let redirect_uri = format!(
        "{}?code={}&state={}",
        query.redirect_uri,
        authorization_code,
        urlencoding::encode(&query.state.clone().unwrap_or_default())
    );
    debug!("Redirecting to: {}", redirect_uri);

    Ok(HttpResponse::Found()
        .header("Location", redirect_uri)
        .finish())
}

// Helper functions
fn is_valid_client(client_id: &str) -> bool {
    // Simulate client validation (only "valid_client" is valid)
    client_id == "valid_client"
}

fn validate_pkce(code_challenge: &str, code_challenge_method: &str) -> bool {
    match code_challenge_method {
        "S256" => !code_challenge.is_empty(), // Support S256 with a valid challenge
        "plain" => !code_challenge.is_empty(), // Optionally support plain method
        _ => {
            error!("Invalid PKCE method: {}", code_challenge_method);
            false // Return false for unsupported methods
        }
    }
}

fn validate_scopes(client_id: &str, scope: &Option<String>) -> bool {
    // Simulate scope validation (only "valid_scope" is allowed)
    match scope.as_deref() {
        Some("valid_scope") => true, // Accept valid scope
        None => true,                // No scope is valid
        _ => false,                  // Invalid scope
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::mock::{MockSessionManager, MockUserAuthenticator};
    use crate::authentication::User;
    use actix_web::cookie::Cookie;
    use actix_web::{test, web, App};
    use std::sync::Arc;

    #[actix_rt::test]
    async fn test_authorize_invalid_client() {
        let mock_authenticator: Arc<dyn UserAuthenticator> = Arc::new(MockUserAuthenticator::new());
        let mock_session_manager: Arc<dyn SessionManager> = Arc::new(MockSessionManager::new());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_authenticator))
                .app_data(web::Data::new(mock_session_manager))
                .route("/authorize", web::get().to(authorize)),
        )
        .await;

        // Invalid client_id
        let req = test::TestRequest::get()
            .uri("/authorize?client_id=invalid_client&response_type=code&redirect_uri=http://localhost/callback")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_authorize_invalid_pkce() {
        let mock_authenticator = Arc::new(MockUserAuthenticator::new());
        let mock_session_manager = Arc::new(MockSessionManager::new());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(
                    mock_authenticator as Arc<dyn UserAuthenticator>,
                ))
                .app_data(web::Data::new(
                    mock_session_manager as Arc<dyn SessionManager>,
                ))
                .route("/authorize", web::get().to(authorize)),
        )
        .await;

        // Invalid PKCE challenge and method
        let req = test::TestRequest::get()
            .uri("/authorize?client_id=valid_client&response_type=code&redirect_uri=http://localhost/callback&code_challenge=challenge&code_challenge_method=invalid")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_authorize_unauthenticated_user() {
        let mock_authenticator = Arc::new(MockUserAuthenticator::new());
        let mock_session_manager = Arc::new(MockSessionManager::new());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(
                    mock_authenticator as Arc<dyn UserAuthenticator>,
                ))
                .app_data(web::Data::new(
                    mock_session_manager as Arc<dyn SessionManager>,
                ))
                .route("/authorize", web::get().to(authorize)),
        )
        .await;

        // No session cookie, user should be redirected to login
        let req = test::TestRequest::get()
            .uri("/authorize?client_id=valid_client&response_type=code&redirect_uri=http://localhost/callback")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 302);
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }

    #[actix_rt::test]
    async fn test_authorize_authenticated_user_with_valid_scope() {
        // Initialize logging
        let _ = env_logger::builder().is_test(true).try_init();

        let mock_authenticator = Arc::new(MockUserAuthenticator::new());
        let mock_session_manager = Arc::new(MockSessionManager::new());

        // Create a valid user and session
        let user = User {
            id: "user1".to_string(),
            username: "alice".to_string(),
        };
        let session_id = "valid_session".to_string();
        mock_session_manager.add_session(&session_id, user).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(
                    mock_authenticator as Arc<dyn UserAuthenticator>,
                ))
                .app_data(web::Data::new(
                    mock_session_manager.clone() as Arc<dyn SessionManager>
                ))
                .route("/authorize", web::get().to(authorize)),
        )
        .await;

        // Create a valid session cookie
        let session_cookie = Cookie::build("session_id", &session_id)
            .path("/")
            .secure(false)
            .finish();

        // Simulate a valid session and a valid client request
        let req = test::TestRequest::get()
        .uri("/authorize?client_id=valid_client&response_type=code&redirect_uri=http://localhost/callback&scope=valid_scope")
        .cookie(session_cookie)
        .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 302); // Redirect after successful authorization
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert!(location.contains("http://localhost/callback"));
    }
}
