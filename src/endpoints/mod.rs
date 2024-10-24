use actix_web::web;

pub mod authorize;
pub mod client_credentials;
pub mod introspection;
pub mod oidc_login;
pub mod register;
pub mod revoke;
pub mod token;
pub use oidc_login::{google_callback_handler, google_login_handler};
pub mod authorize_user;
pub mod delete;
pub mod login;
pub mod update;

pub fn init_routes<A, S>(cfg: &mut web::ServiceConfig)
where
    A: 'static + crate::authentication::UserAuthenticator,
    S: 'static + crate::authentication::SessionManager,
{
    // Route configurations...
}
