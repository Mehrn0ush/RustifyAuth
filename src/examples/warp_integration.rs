use warp::Filter;
use rustify_auth::core::token::generate_token;

#[tokio::main]
async fn main() {
    // Define a warp route that generates a token
    let token_route = warp::path("token")
        .map(|| {
            let token = generate_token();
            warp::reply::html(token)
        });

    // Start the warp server
    warp::serve(token_route)
        .run(([127, 0, 0, 1], 8080))
        .await;
}
