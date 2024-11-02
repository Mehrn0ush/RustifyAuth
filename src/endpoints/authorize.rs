use crate::authentication::User;
use crate::authentication::{AuthError, SessionManager, UserAuthenticator};
use crate::config::OidcConfig;
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
    config: web::Data<OidcConfig>,
    authenticator: web::Data<Arc<dyn UserAuthenticator + Send + Sync>>,
    session_manager: web::Data<Arc<dyn SessionManager + Send + Sync>>,
    req: HttpRequest,
) -> Result<HttpResponse, Error> {
    let query = match query {
        Ok(q) => q.into_inner(),
        Err(e) => {
            error!("Failed to parse query parameters: {}", e);
            return Ok(HttpResponse::BadRequest().body("Invalid query parameters"));
        }
    };

    debug!("Authorization request received: {:?}", query);
    debug!("Starting authorization process");

    // Step 1: Validate the client information
    debug!("Validating client_id: {}", query.client_id);
    if !is_valid_client(&query.client_id) {
        error!("Invalid client_id: {}", query.client_id);
        return Ok(HttpResponse::BadRequest().body("Invalid client_id"));
    }
    debug!("Client ID validated");

    // Step 2: Handle PKCE if provided
    if let (Some(code_challenge), Some(code_challenge_method)) =
        (&query.code_challenge, &query.code_challenge_method)
    {
        debug!(
            "Validating PKCE: code_challenge={}, code_challenge_method={}",
            code_challenge, code_challenge_method
        );
        if !validate_pkce(code_challenge, code_challenge_method) {
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
            Ok(user) => {
                debug!("Session manager returned user: {:?}", user);
                user
            }
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
    debug!(
        "Validating scopes: client_id={}, scope={:?}",
        query.client_id, query.scope
    );
    if !validate_scopes(&query.client_id, &query.scope) {
        error!("Invalid scope for client_id: {}", query.client_id);
        return Ok(HttpResponse::BadRequest().body("Invalid scope"));
    }
    debug!("Scope validated");

    // Step 5: Handle different response types based on configuration
    match query.response_type.as_str() {
        "code" if config.authorization_code_flow => {
            debug!("Handling authorization code flow");
            handle_authorization_code_flow(query, user).await
        }
        "token" | "id_token" if config.implicit_flow => {
            debug!("Handling implicit flow");
            handle_implicit_flow(query, user).await
        }
        "code token" | "code id_token" | "code token id_token" if config.hybrid_flow => {
            debug!("Handling hybrid flow");
            handle_hybrid_flow(query, user).await
        }
        _ => {
            error!(
                "Unsupported or disabled response_type: {}",
                query.response_type
            );
            Ok(HttpResponse::BadRequest().body("Unsupported or disabled response_type"))
        }
    }
}

// Implementations for different flows

async fn handle_authorization_code_flow(
    query: AuthorizationRequest,
    user: User,
) -> Result<HttpResponse, Error> {
    // Generate authorization code
    let authorization_code = generate_authorization_code();
    debug!("Authorization code generated: {}", authorization_code);

    // Build redirect URI
    let mut redirect_uri = format!("{}?code={}", query.redirect_uri, authorization_code);

    if let Some(state) = query.state {
        redirect_uri = format!("{}&state={}", redirect_uri, urlencoding::encode(&state));
    }

    debug!("Redirecting to: {}", redirect_uri);

    Ok(HttpResponse::Found()
        .header("Location", redirect_uri)
        .finish())
}

async fn handle_implicit_flow(
    query: AuthorizationRequest,
    user: User,
) -> Result<HttpResponse, Error> {
    // Generate ID token and/or access token
    let id_token = if query.response_type.contains("id_token") {
        Some(generate_id_token(&user, &query)?)
    } else {
        None
    };

    let access_token = if query.response_type.contains("token") {
        Some(generate_access_token(&user, &query)?)
    } else {
        None
    };

    // Build fragment response
    let mut fragment_params = vec![];

    if let Some(token) = access_token {
        fragment_params.push(format!("access_token={}", token));
    }
    if let Some(token) = id_token {
        fragment_params.push(format!("id_token={}", token));
    }
    if let Some(state) = query.state {
        fragment_params.push(format!("state={}", urlencoding::encode(&state)));
    }

    let fragment = fragment_params.join("&");
    let redirect_uri = format!("{}#{}", query.redirect_uri, fragment);

    debug!("Redirecting to: {}", redirect_uri);

    Ok(HttpResponse::Found()
        .header("Location", redirect_uri)
        .finish())
}

async fn handle_hybrid_flow(
    query: AuthorizationRequest,
    user: User,
) -> Result<HttpResponse, Error> {
    // Generate authorization code, ID token, and/or access token
    let authorization_code = generate_authorization_code();
    let id_token = if query.response_type.contains("id_token") {
        Some(generate_id_token(&user, &query)?)
    } else {
        None
    };
    let access_token = if query.response_type.contains("token") {
        Some(generate_access_token(&user, &query)?)
    } else {
        None
    };

    // Build response parameters
    let mut params = vec![format!("code={}", authorization_code)];
    let mut fragment_params = vec![];

    if let Some(token) = access_token {
        fragment_params.push(format!("access_token={}", token));
    }
    if let Some(token) = id_token {
        fragment_params.push(format!("id_token={}", token));
    }
    if let Some(state) = query.state {
        let encoded_state = urlencoding::encode(&state);
        params.push(format!("state={}", encoded_state));
        fragment_params.push(format!("state={}", encoded_state));
    }

    let query_string = params.join("&");
    let fragment = fragment_params.join("&");
    let redirect_uri = format!("{}?{}#{}", query.redirect_uri, query_string, fragment);

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

fn generate_id_token(user: &User, query: &AuthorizationRequest) -> Result<String, Error> {
    // Implement ID token generation logic
    Ok("id_token_placeholder".to_string())
}

fn generate_access_token(user: &User, query: &AuthorizationRequest) -> Result<String, Error> {
    // Implement access token generation logic
    Ok("access_token_placeholder".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::mock::{MockSessionManager, MockUserAuthenticator};
    use crate::authentication::User;
    use crate::config::OidcConfig;

    use actix_web::cookie::Cookie;
    use actix_web::{test, web, App};
    use std::sync::Arc;

    #[actix_rt::test]
    async fn test_authorize_invalid_client() {
        // Initialize logging for the test
        let _ = env_logger::builder().is_test(true).try_init();

        // Instantiate mocks as concrete types
        let mock_authenticator = Arc::new(MockUserAuthenticator::new());
        let mock_session_manager = Arc::new(MockSessionManager::new());
        let config = OidcConfig::default();

        // Initialize the Actix-web app with trait object clones
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(
                    mock_authenticator.clone() as Arc<dyn UserAuthenticator + Send + Sync>
                ))
                .app_data(web::Data::new(
                    mock_session_manager.clone() as Arc<dyn SessionManager + Send + Sync>
                ))
                .route("/authorize", web::get().to(authorize)),
        )
        .await;

        // Construct a request with an invalid client_id
        let req = test::TestRequest::get()
            .uri("/authorize?client_id=invalid_client&response_type=code&redirect_uri=http://localhost/callback")
            .to_request();

        let resp = test::call_service(&app, req).await;

        // **Check the status and headers first**
        let status = resp.status();
        let resp_body = test::read_body(resp).await;
        let resp_body_str = match std::str::from_utf8(&resp_body) {
            Ok(s) => s,
            Err(_) => "<Invalid UTF-8>",
        };
        println!("Response status: {}", status);
        println!("Response body: {}", resp_body_str);

        // Assert that the response status is 400 Bad Request
        assert_eq!(status, 400, "Expected status 400, got {}", status);
    }

    #[actix_rt::test]
    async fn test_authorize_invalid_pkce() {
        // Initialize logging for the test
        let _ = env_logger::builder().is_test(true).try_init();

        // Instantiate mocks as concrete types
        let mock_authenticator = Arc::new(MockUserAuthenticator::new());
        let mock_session_manager = Arc::new(MockSessionManager::new());
        let config = OidcConfig::default();

        // Initialize the Actix-web app with trait object clones
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(
                    mock_authenticator.clone() as Arc<dyn UserAuthenticator + Send + Sync>
                ))
                .app_data(web::Data::new(
                    mock_session_manager.clone() as Arc<dyn SessionManager + Send + Sync>
                ))
                .route("/authorize", web::get().to(authorize)),
        )
        .await;

        // Construct a request with invalid PKCE parameters
        let req = test::TestRequest::get()
            .uri("/authorize?client_id=valid_client&response_type=code&redirect_uri=http://localhost/callback&code_challenge=challenge&code_challenge_method=invalid")
            .to_request();

        let resp = test::call_service(&app, req).await;

        // **Check the status and headers first**
        let status = resp.status();
        let resp_body = test::read_body(resp).await;
        let resp_body_str = match std::str::from_utf8(&resp_body) {
            Ok(s) => s,
            Err(_) => "<Invalid UTF-8>",
        };
        println!("Response status: {}", status);
        println!("Response body: {}", resp_body_str);

        // Assert that the response status is 400 Bad Request
        assert_eq!(status, 400, "Expected status 400, got {}", status);
    }

    #[actix_rt::test]
    async fn test_authorize_unauthenticated_user() {
        // Initialize logging for the test
        let _ = env_logger::builder().is_test(true).try_init();

        // Instantiate mocks as concrete types
        let mock_authenticator = Arc::new(MockUserAuthenticator::new());
        let mock_session_manager = Arc::new(MockSessionManager::new());
        let config = OidcConfig::default();

        // Initialize the Actix-web app with trait object clones
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(
                    mock_authenticator.clone() as Arc<dyn UserAuthenticator + Send + Sync>
                ))
                .app_data(web::Data::new(
                    mock_session_manager.clone() as Arc<dyn SessionManager + Send + Sync>
                ))
                .route("/authorize", web::get().to(authorize)),
        )
        .await;

        // Construct a request without a session cookie (unauthenticated user)
        let req = test::TestRequest::get()
            .uri("/authorize?client_id=valid_client&response_type=code&redirect_uri=http://localhost/callback")
            .to_request();

        let resp = test::call_service(&app, req).await;

        // **Check the status and headers first**
        let status = resp.status();
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        println!("Response status: {}", status);
        println!("Redirect location: {}", location);

        // **Assert the response**
        assert_eq!(status, 302, "Expected status 302, got {}", status);
        assert_eq!(
            location, "/login",
            "Expected redirect to /login, got {}",
            location
        );
    }

    #[actix_rt::test]
    async fn test_authorize_authenticated_user_with_valid_scope() {
        // Initialize logging for the test
        let _ = env_logger::builder().is_test(true).try_init();

        // Instantiate mocks as concrete types
        let mock_authenticator = Arc::new(MockUserAuthenticator::new());
        let mock_session_manager = Arc::new(MockSessionManager::new());
        let config = OidcConfig::default();

        // Create a valid user and session
        let user = User {
            id: "user1".to_string(),
            username: "alice".to_string(),
        };
        let session_id = "valid_session".to_string();

        // Mock the session manager to return the user when the session_id is valid
        mock_session_manager.add_session(&session_id, user).await;

        // Initialize the Actix-web app with trait object clones
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(
                    mock_authenticator.clone() as Arc<dyn UserAuthenticator + Send + Sync>
                ))
                .app_data(web::Data::new(
                    mock_session_manager.clone() as Arc<dyn SessionManager + Send + Sync>
                ))
                .route("/authorize", web::get().to(authorize)),
        )
        .await;

        // Create a valid session cookie
        let session_cookie = Cookie::build("session_id", &session_id)
            .path("/")
            .secure(false)
            .finish();

        // Construct a request with a valid session and scope
        let req = test::TestRequest::get()
        .uri("/authorize?client_id=valid_client&response_type=code&redirect_uri=http://localhost/callback&scope=valid_scope")
        .cookie(session_cookie)
        .to_request();

        let resp = test::call_service(&app, req).await;

        // **Check the status and headers first**
        let status = resp.status();
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        println!("Response status: {}", status);
        println!("Redirect location: {}", location);

        // **Assert the response**
        assert_eq!(status, 302, "Expected status 302, got {}", status);
        assert!(location.contains("http://localhost/callback"));
    }
}
