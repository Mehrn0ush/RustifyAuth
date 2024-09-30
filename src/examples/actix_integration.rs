use actix_web::{get, App, HttpServer, HttpResponse};
use rustify_auth::core::token::generate_token;
use routes::{auth, users};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            // User routes
            .route("/register", web::post().to(users::register::<MyUserAuthenticator>))
            .route("/login", web::post().to(users::login::<MyUserAuthenticator, MySessionManager>))
            .route("/logout", web::post().to(users::logout::<MySessionManager>))
            .route("/profile", web::get().to(users::view_profile::<MySessionManager>))
            // OAuth2 routes
            .route("/authorize", web::get().to(auth::authorize::<MyUserAuthenticator, MySessionManager>))
            .route("/token", web::post().to(auth::token))
            .route("/revoke", web::post().to(auth::revoke))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}