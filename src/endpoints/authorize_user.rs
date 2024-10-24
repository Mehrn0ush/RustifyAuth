use crate::core::device_flow::{DeviceCode, DeviceCodeStore};
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

// Struct for User Authorization Request
#[derive(Debug, Serialize, Deserialize)]
pub struct UserAuthorizationRequest {
    pub user_code: String,
}

// Struct for User Authorization Response
#[derive(Debug, Serialize, Deserialize)]
pub struct UserAuthorizationResponse {
    pub success: bool,
    pub message: String,
}

// User Authorization Endpoint
pub async fn user_authorization_endpoint(
    req: web::Json<UserAuthorizationRequest>,
    store: web::Data<DeviceCodeStore>,
) -> HttpResponse {
    let success = store.authorize_device_code(&req.user_code);

    if success {
        HttpResponse::Ok().json(UserAuthorizationResponse {
            success: true,
            message: "Device authorized successfully.".to_string(),
        })
    } else {
        HttpResponse::BadRequest().json(UserAuthorizationResponse {
            success: false,
            message: "Invalid or expired user code.".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_user_authorization_success() {
        let store = web::Data::new(DeviceCodeStore::new());

        // Add a device code for testing
        store.store_device_code(DeviceCode {
            device_code: "device123".to_string(),
            user_code: "user123".to_string(),
            client_id: "client123".to_string(),
            expires_at: 0, // Set it in the past for simplicity
            authorized: false,
        });

        // Simulate user entering the user code
        let req_body = UserAuthorizationRequest {
            user_code: "user123".to_string(),
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/authorize_user",
            web::post().to(user_authorization_endpoint),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/authorize_user")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let resp_body: UserAuthorizationResponse = test::read_body_json(resp).await;
        assert!(resp_body.success);
        assert_eq!(resp_body.message, "Device authorized successfully.");

        // Check if the device code is now authorized
        let device_code = store.find_device_code("device123").unwrap();
        assert!(device_code.authorized);
    }

    #[actix_web::test]
    async fn test_user_authorization_invalid_code() {
        let store = web::Data::new(DeviceCodeStore::new());

        // Simulate user entering an invalid user code
        let req_body = UserAuthorizationRequest {
            user_code: "invalid_code".to_string(),
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/authorize_user",
            web::post().to(user_authorization_endpoint),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/authorize_user")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);

        let resp_body: UserAuthorizationResponse = test::read_body_json(resp).await;
        assert!(!resp_body.success);
        assert_eq!(resp_body.message, "Invalid or expired user code.");
    }
}
