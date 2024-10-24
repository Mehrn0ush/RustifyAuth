use crate::core::device_flow::{
    device_token_endpoint, DeviceCode, DeviceTokenRequest, DeviceTokenResponse,
};
use crate::core::token::{InMemoryTokenStore, TokenStore};
use crate::DeviceCodeStore;
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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
    use crate::core::device_flow::DeviceCode;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_user_authorization_success() {
        let store = web::Data::new(DeviceCodeStore::new());

        // Add a device code for testing
        store.store_device_code(DeviceCode {
            device_code: "test_device_code".to_string(),
            user_code: "user123".to_string(),
            client_id: "client123".to_string(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600, // Expires in 10 minutes
            authorized: true,
            scopes: Some("read write".to_string()), // Add requested scopes
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
        let device_code = store.find_device_code("test_device_code").unwrap();
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

    #[actix_web::test]
    async fn test_device_token_with_scopes() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());

        let device_code = "test_device_code".to_string();

        // Add a device code with a valid scope
        store.store_device_code(DeviceCode {
            device_code: device_code.clone(),
            user_code: "user123".to_string(),
            client_id: "client123".to_string(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600, // Expires in 10 minutes
            authorized: true,
            scopes: Some("read write".to_string()), // Requested scopes
        });

        let req_body = DeviceTokenRequest {
            client_id: "client123".to_string(),
            device_code: device_code.clone(),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(token_store.clone())
                .route("/device_token", web::post().to(device_token_endpoint)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/device_token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let resp_body: DeviceTokenResponse = test::read_body_json(resp).await;
        assert!(resp_body.access_token.is_some());
    }
}
