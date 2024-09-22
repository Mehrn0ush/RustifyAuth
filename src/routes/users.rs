use crate::authentication::{AuthError, UserAuthenticator, SessionManager};
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use std::sync::Arc;


#[derive(Deserialize)]
pub struct RegisterRequest {
    username: String,
    password: String,
    // Additional fields as needed (e.g., email)
}

pub async fn register<A: UserAuthenticator>(
    form: web::Form<RegisterRequest>,
    authenticator: web::Data<Arc<A>>,
) -> Result<HttpResponse> {
    // For now, mock user registration logic
    // You can later extend this to interact with a database
    match authenticator.authenticate(&form.username, &form.password).await {
        Ok(_) => Ok(HttpResponse::Created().body("User registered successfully")),
        Err(_) => Ok(HttpResponse::InternalServerError().body("Registration failed")),
    }
}


#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

pub async fn login<A: UserAuthenticator, S: SessionManager>(
    form: web::Form<LoginRequest>,
    authenticator: web::Data<Arc<A>>,
    session_manager: web::Data<Arc<S>>,
) -> Result<HttpResponse> {
    match authenticator.authenticate(&form.username, &form.password).await {
        Ok(user) => {
            let session_id = session_manager.create_session(&user).await.unwrap();
            Ok(HttpResponse::Found()
                .header("Set-Cookie", format!("session_id={}; HttpOnly", session_id))
                .header("Location", "/profile") // Redirect to profile page
                .finish())
        }
        Err(AuthError::InvalidCredentials) => Ok(HttpResponse::Unauthorized().body("Invalid credentials")),
        Err(_) => Ok(HttpResponse::InternalServerError().body("Login failed")),
    }
}

pub async fn logout<S: SessionManager>(
    session_manager: web::Data<Arc<S>>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    if let Some(session_cookie) = req.cookie("session_id") {
        session_manager.destroy_session(session_cookie.value()).await.unwrap();
        Ok(HttpResponse::Found().header("Set-Cookie", "session_id=; Max-Age=0").finish())
    } else {
        Ok(HttpResponse::BadRequest().body("No session found"))
    }
}


pub async fn view_profile<S: SessionManager>(
    session_manager: web::Data<Arc<S>>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    if let Some(session_cookie) = req.cookie("session_id") {
        match session_manager.get_user_by_session(session_cookie.value()).await {
            Ok(user) => Ok(HttpResponse::Ok().json(user)), // Return user details in JSON
            Err(_) => Ok(HttpResponse::Unauthorized().body("Unauthorized")),
        }
    } else {
        Ok(HttpResponse::Unauthorized().body("No session found"))
    }
}
