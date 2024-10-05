use crate::authentication::{AuthError, SessionManager, UserAuthenticator};
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
    // Additional fields as needed
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

/*

Notes:

This login endpoint uses the UserAuthenticator and SessionManager to authenticate users and manage sessions.
It sets a session_id cookie upon successful login.
Users of the library can implement their own UserAuthenticator and SessionManager to customize the authentication process.
*/
