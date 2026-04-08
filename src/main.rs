#[actix_web::main]
async fn main() -> std::io::Result<()> {
    rustify_auth::run_mock_server(("127.0.0.1", 8080)).await
}
