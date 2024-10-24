use crate::core::token::{InMemoryTokenStore, TokenStore};
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// Structs for Device Flow

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceTokenRequest {
    pub client_id: String,
    pub device_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceTokenResponse {
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub expires_at: u64,
    pub authorized: bool,
}

// In-memory storage for device codes
#[derive(Debug, Clone)]
pub struct DeviceCodeStore {
    pub device_codes: Arc<RwLock<Vec<DeviceCode>>>,
}

impl DeviceCodeStore {
    pub fn new() -> Self {
        Self {
            device_codes: Arc::new(RwLock::new(vec![])),
        }
    }

    pub fn store_device_code(&self, device_code: DeviceCode) {
        self.device_codes.write().unwrap().push(device_code);
    }

    pub fn find_device_code(&self, device_code: &str) -> Option<DeviceCode> {
        self.device_codes
            .read()
            .unwrap()
            .iter()
            .find(|code| code.device_code == device_code)
            .cloned()
    }

    pub fn authorize_device_code(&self, user_code: &str) -> bool {
        let mut device_codes = self.device_codes.write().unwrap();
        if let Some(mut device_code) = device_codes
            .iter_mut()
            .find(|code| code.user_code == user_code)
        {
            device_code.authorized = true;
            return true;
        }
        false
    }
}

// Device Authorization Endpoint
pub async fn device_authorization_endpoint(
    req: web::Json<DeviceAuthorizationRequest>,
    store: web::Data<DeviceCodeStore>,
) -> HttpResponse {
    let device_code = Uuid::new_v4().to_string();
    let user_code = Uuid::new_v4()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>(); // Generate 8-char user code

    let expires_in = 600; // 10 minutes
    let interval = 5; // Polling interval in seconds

    // Store device code
    let device_code_obj = DeviceCode {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        client_id: req.client_id.clone(),
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + expires_in,
        authorized: false,
    };

    store.store_device_code(device_code_obj);

    HttpResponse::Ok().json(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri: "https://yourdomain.com/device".to_string(), // Your device verification page
        expires_in,
        interval,
    })
}

// Device Token Polling Endpoint
pub async fn device_token_endpoint(
    req: web::Json<DeviceTokenRequest>,
    store: web::Data<DeviceCodeStore>,
    token_store: web::Data<InMemoryTokenStore>,
) -> HttpResponse {
    if let Some(device_code_obj) = store.find_device_code(&req.device_code) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time > device_code_obj.expires_at {
            return HttpResponse::BadRequest().json(DeviceTokenResponse {
                access_token: None,
                token_type: None,
                error: Some("expired_token".to_string()),
            });
        }

        if !device_code_obj.authorized {
            return HttpResponse::BadRequest().json(DeviceTokenResponse {
                access_token: None,
                token_type: None,
                error: Some("authorization_pending".to_string()),
            });
        }

        // Generate and return access token
        let access_token = Uuid::new_v4().to_string(); // Generate token
        token_store
            .store_access_token(
                &access_token,
                &device_code_obj.client_id,
                "user_id",
                current_time + 3600,
            )
            .unwrap();

        HttpResponse::Ok().json(DeviceTokenResponse {
            access_token: Some(access_token),
            token_type: Some("Bearer".to_string()),
            error: None,
        })
    } else {
        HttpResponse::BadRequest().json(DeviceTokenResponse {
            access_token: None,
            token_type: None,
            error: Some("invalid_request".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_device_authorization_success() {
        let store = web::Data::new(DeviceCodeStore::new());

        let req_body = DeviceAuthorizationRequest {
            client_id: "test_client_id".to_string(),
        };

        let app = test::init_service(App::new().app_data(store.clone()).route(
            "/device_authorize",
            web::post().to(device_authorization_endpoint),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/device_authorize")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let resp_body: DeviceAuthorizationResponse = test::read_body_json(resp).await;
        assert!(!resp_body.device_code.is_empty());
        assert!(!resp_body.user_code.is_empty());
    }

    #[actix_web::test]
    async fn test_device_token_pending() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());

        // Assuming `device_authorization_endpoint` was already called, and we have a device code
        let device_code = "test_device_code".to_string();

        let req_body = DeviceTokenRequest {
            client_id: "test_client_id".to_string(),
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
        assert_eq!(resp.status(), 400); // Authorization pending
    }
}
