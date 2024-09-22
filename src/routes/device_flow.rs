use crate::core::extension_grants::{DefaultDeviceFlowHandler, DeviceFlowHandler};
use crate::core::types::TokenError;
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct DeviceAuthorizationRequest {
    client_id: String,
    scope: Option<String>,
}

pub async fn device_authorize(
    query: web::Query<DeviceAuthorizationRequest>,
) -> Result<HttpResponse> {
    // Generate a device code and return it
    let device_handler = DefaultDeviceFlowHandler {
        verification_uri_base: "https://example.com/device".to_string(), // Add the missing field
    };
    let device_code_response = device_handler.generate_device_code();

    Ok(HttpResponse::Ok().json(device_code_response))
}

#[derive(Deserialize)]
pub struct DeviceTokenRequest {
    device_code: String,
}

pub async fn device_token(body: web::Form<DeviceTokenRequest>) -> Result<HttpResponse> {
    let device_handler = DefaultDeviceFlowHandler {
        verification_uri_base: "https://example.com/device".to_string(),
    };

    match device_handler.poll_device_code(&body.device_code) {
        Ok(token_response) => Ok(HttpResponse::Ok().json(token_response)),
        Err(e) => Err(e.into()), // Now that TokenError implements ResponseError, this works
    }
}
