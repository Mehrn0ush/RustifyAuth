use crate::core::client_credentials::{validate_client_credentials, issue_token};
use crate::endpoints::token::{TokenRequest, TokenResponse};
use actix_web::{web, HttpResponse};

pub async fn handle_client_credentials(
    req: web::Json<TokenRequest>
) -> HttpResponse {
    // Validate the request parameters
    if req.grant_type != "client_credentials" {
        return HttpResponse::BadRequest().json("invalid grant_type");
    }

    // Call core functions to validate client and issue token
    match validate_client_credentials(&req.client_id, &req.client_secret) {
        Ok(client) => match issue_token(&client, &req.scope) {
            Ok(token_response) => HttpResponse::Ok().json(token_response),
            Err(err) => HttpResponse::InternalServerError().json(err),
        },
        Err(err) => HttpResponse::Unauthorized().json(err),
    }
}
