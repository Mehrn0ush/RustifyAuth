use actix_web::{get, App, HttpServer, HttpResponse};
use rustify_auth::core::token::generate_token;

#[get("/token")]
async fn get_token() -> HttpResponse {
    let token = generate_token();
    HttpResponse::Ok().body(token)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(get_token)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
