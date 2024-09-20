#[macro_use] extern crate rocket;
use rocket::response::status::Custom;
use rocket::http::Status;
use rustify_auth::core::token::generate_token;

#[get("/token")]
fn get_token() -> Custom<String> {
    let token = generate_token();
    Custom(Status::Ok, token)
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![get_token])
}
