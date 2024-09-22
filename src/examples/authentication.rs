use my_auth_library::authentication::{MockSessionManager, MockUserAuthenticator};
use my_auth_library::endpoints::{authorize, login};
use actix_web::{web, App, HttpServer};
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let authenticator = Arc::new(MockUserAuthenticator::new());
    let session_manager = Arc::new(MockSessionManager::new());

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(authenticator.clone()))
            .app_data(web::Data::new(session_manager.clone()))
            .route("/authorize", web::get().to(authorize::<MockUserAuthenticator, MockSessionManager>))
            .route("/login", web::post().to(login::<MockUserAuthenticator, MockSessionManager>))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

/*
Notes:

In this example, the application uses the mock implementations provided by the library.
Users can replace MockUserAuthenticator and MockSessionManager with their own implementations.
*/