pub mod auth;
pub mod device_flow;
pub mod users;

use actix_web::web;

pub fn init_routes<A, S>(cfg: &mut web::ServiceConfig)
where
    A: 'static + crate::authentication::UserAuthenticator,
    S: 'static + crate::authentication::SessionManager,
{
    cfg.service(
        web::resource("/authorize").route(web::get().to(auth::authorize)), // Remove generic parameters here
    );
    cfg.service(web::resource("/device/code").route(web::post().to(device_flow::device_authorize)));
    cfg.service(web::resource("/device/token").route(web::post().to(device_flow::device_token)));
}
