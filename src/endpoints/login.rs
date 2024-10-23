use crate::authentication::{AuthError, SessionManager, User, UserAuthenticator};
use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize, Serialize)] // Added Serialize
pub struct LoginRequest {
    username: String,
    password: String,
}

pub async fn login<A: UserAuthenticator, S: SessionManager>(
    form: web::Form<LoginRequest>,
    authenticator: web::Data<Arc<A>>,
    session_manager: web::Data<Arc<S>>,
) -> Result<HttpResponse> {
    // Authenticate the user
    match authenticator
        .authenticate(&form.username, &form.password)
        .await
    {
        Ok(user) => {
            // Create a new session
            let session_id = session_manager.create_session(&user).await.unwrap();

            // Set the session ID in a cookie
            Ok(HttpResponse::Found()
                .header("Set-Cookie", format!("session_id={}; HttpOnly", session_id))
                .header("Location", "/") // Redirect to home or original URL
                .finish())
        }
        Err(AuthError::InvalidCredentials) => {
            Ok(HttpResponse::Unauthorized().body("Invalid credentials"))
        }
        Err(_) => Ok(HttpResponse::InternalServerError().body("Internal server error")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::header, test, web, App};
    use async_trait::async_trait;
    use std::sync::Arc;

    // Mock UserAuthenticator for testing
    struct MockAuthenticator;

    #[async_trait]
    impl UserAuthenticator for MockAuthenticator {
        async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError> {
            if username == "valid_user" && password == "valid_password" {
                Ok(User {
                    id: "user_id".to_string(),
                    username: "valid_user".to_string(),
                })
            } else if username == "invalid_user" {
                Err(AuthError::InvalidCredentials)
            } else {
                Err(AuthError::InternalError)
            }
        }

        async fn is_authenticated(&self, _session_id: &str) -> Result<User, AuthError> {
            Ok(User {
                id: "user_id".to_string(),
                username: "valid_user".to_string(),
            })
        }
    }

    // Mock SessionManager for testing
    struct MockSessionManager;

    #[async_trait]
    impl SessionManager for MockSessionManager {
        async fn create_session(&self, _user: &User) -> Result<String, AuthError> {
            Ok("session_id_123".to_string())
        }

        async fn get_user_by_session(&self, _session_id: &str) -> Result<User, AuthError> {
            Ok(User {
                id: "user_id".to_string(),
                username: "valid_user".to_string(),
            })
        }

        async fn destroy_session(&self, _session_id: &str) -> Result<(), AuthError> {
            Ok(())
        }
    }

    #[actix_rt::test]
    async fn test_login_success() {
        let authenticator = Arc::new(MockAuthenticator);
        let session_manager = Arc::new(MockSessionManager);

        let mut app = test::init_service(
            App::new()
                .app_data(web::Data::new(authenticator.clone()))
                .app_data(web::Data::new(session_manager.clone()))
                .service(
                    web::resource("/login")
                        .route(web::post().to(login::<MockAuthenticator, MockSessionManager>)),
                ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/login")
            .set_form(&LoginRequest {
                username: "valid_user".to_string(),
                password: "valid_password".to_string(),
            })
            .to_request();

        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 302); // Found (Redirect)
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/");
        assert!(resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("session_id=session_id_123"));
    }

    #[actix_rt::test]
    async fn test_login_invalid_credentials() {
        let authenticator = Arc::new(MockAuthenticator);
        let session_manager = Arc::new(MockSessionManager);

        let mut app = test::init_service(
            App::new()
                .app_data(web::Data::new(authenticator.clone()))
                .app_data(web::Data::new(session_manager.clone()))
                .service(
                    web::resource("/login")
                        .route(web::post().to(login::<MockAuthenticator, MockSessionManager>)),
                ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/login")
            .set_form(&LoginRequest {
                username: "invalid_user".to_string(),
                password: "invalid_password".to_string(),
            })
            .to_request();

        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 401); // Unauthorized
        let body = test::read_body(resp).await;
        assert_eq!(body, "Invalid credentials");
    }

    #[actix_rt::test]
    async fn test_login_internal_error() {
        let authenticator = Arc::new(MockAuthenticator);
        let session_manager = Arc::new(MockSessionManager);

        let mut app = test::init_service(
            App::new()
                .app_data(web::Data::new(authenticator.clone()))
                .app_data(web::Data::new(session_manager.clone()))
                .service(
                    web::resource("/login")
                        .route(web::post().to(login::<MockAuthenticator, MockSessionManager>)),
                ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/login")
            .set_form(&LoginRequest {
                username: "any_user".to_string(),
                password: "error".to_string(),
            })
            .to_request();

        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 500); // Internal Server Error
        let body = test::read_body(resp).await;
        assert_eq!(body, "Internal server error");
    }
}
