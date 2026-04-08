pub mod auth;
pub mod device_flow;
pub mod users;
use crate::core::token::InMemoryTokenStore;
use crate::endpoints::authorize::authorize;
use crate::endpoints::delete::delete_client_handler;
use crate::endpoints::introspection::introspect_token;
use crate::endpoints::login::login;
use crate::endpoints::register::register_client_handler;
use crate::endpoints::revoke::revoke_token_endpoint;
use crate::endpoints::token::token_endpoint;
use crate::endpoints::update::update_client_handler;
use actix_web::web;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/authorize").route(web::get().to(authorize)));
    cfg.service(web::resource("/login").route(web::post().to(login)));
    cfg.service(web::resource("/device/code").route(web::post().to(device_flow::device_authorize)));
    cfg.service(web::resource("/device/token").route(web::post().to(device_flow::device_token)));

    cfg.service(
        web::resource("/register")
            .route(web::post().to(register_client_handler::<InMemoryTokenStore>)),
    );
    cfg.service(
        web::resource("/update/{client_id}")
            .route(web::put().to(update_client_handler::<InMemoryTokenStore>)),
    );
    cfg.service(
        web::resource("/delete/{client_id}")
            .route(web::delete().to(delete_client_handler::<InMemoryTokenStore>)),
    );
    // Register other endpoints similarly...
    cfg.service(web::resource("/token").route(web::post().to(token_endpoint)));
    cfg.service(web::resource("/introspection").route(web::post().to(introspect_token)));
    cfg.service(web::resource("/revoke").route(web::post().to(revoke_token_endpoint)));
}
