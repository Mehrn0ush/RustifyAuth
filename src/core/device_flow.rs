use crate::core::token::{InMemoryTokenStore, TokenStore};
use crate::security::rate_limit::RateLimiter;
use actix_web::rt::time::interval;
use actix_web::{web, HttpResponse};
use log::{error, info}; // Added logging
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub fn start_device_code_cleanup(store: web::Data<DeviceCodeStore>) {
    actix_web::rt::spawn(async move {
        let mut cleanup_interval = interval(Duration::from_secs(60)); // Run cleanup every minute
        loop {
            cleanup_interval.tick().await;
            store.cleanup_expired_codes();
        }
    });
}

// Structs for Device Flow

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    pub scope: Option<String>,
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
    pub scopes: Option<String>,
}
// Configuration struct for device flow settings
#[derive(Debug, Clone)]
pub struct DeviceFlowConfig {
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
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
            info!(
                "Device code '{}' authorized successfully.",
                device_code.device_code
            ); // Logging success
            return true;
        }
        error!(
            "Failed to authorize device code for user_code '{}'. Code not found or expired.",
            user_code
        ); // Logging error
        false
    }

    pub fn cleanup_expired_codes(&self) {
        let mut device_codes = self.device_codes.write().unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let initial_count = device_codes.len();
        device_codes.retain(|code| code.expires_at > current_time);

        let removed_count = initial_count - device_codes.len();
        if removed_count > 0 {
            info!("Cleaned up {} expired device codes.", removed_count); // Logging cleanup
        }
    }
}

// Device Authorization Endpoint
pub async fn device_authorization_endpoint(
    req: web::Json<DeviceAuthorizationRequest>,
    store: web::Data<DeviceCodeStore>,
    config: web::Data<DeviceFlowConfig>,
) -> HttpResponse {
    let device_code = Uuid::new_v4().to_string();
    let user_code = Uuid::new_v4()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>(); // Generate 8-char user code

    let expires_in = 600; // 10 minutes
    let interval = 5; // Polling interval in seconds

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
        scopes: req.scope.clone(),
    };

    store.store_device_code(device_code_obj);
    info!(
        "Device code '{}' created for client '{}'.",
        device_code, req.client_id
    ); // Logging code creation

    HttpResponse::Ok().json(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri: config.verification_uri.clone(), // Your device verification page
        expires_in,
        interval,
    })
}

// Device Token Polling Endpoint
pub async fn device_token_endpoint(
    req: web::Json<DeviceTokenRequest>,
    store: web::Data<DeviceCodeStore>,
    token_store: web::Data<InMemoryTokenStore>,
    rate_limiter: web::Data<RateLimiter>,
) -> HttpResponse {
    let client_id = &req.client_id;

    // Check if client is rate-limited
    if rate_limiter.is_rate_limited(client_id) {
        return HttpResponse::TooManyRequests().json(DeviceTokenResponse {
            access_token: None,
            token_type: None,
            error: Some("rate_limit_exceeded".to_string()),
        });
    }

    match store.find_device_code(&req.device_code) {
        Some(device_code_obj) => {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if current_time > device_code_obj.expires_at {
                error!("Device code '{}' has expired.", req.device_code);
                return HttpResponse::BadRequest().json(DeviceTokenResponse {
                    access_token: None,
                    token_type: None,
                    error: Some("expired_token".to_string()),
                });
            }

            if !device_code_obj.authorized {
                info!(
                    "Authorization pending for device code '{}'.",
                    req.device_code
                );
                return HttpResponse::BadRequest().json(DeviceTokenResponse {
                    access_token: None,
                    token_type: None,
                    error: Some("authorization_pending".to_string()),
                });
            }

            let access_token = Uuid::new_v4().to_string();
            if let Err(e) = token_store.store_access_token(
                &access_token,
                &device_code_obj.client_id,
                "user_id",
                current_time + 3600,
            ) {
                error!("Failed to store access token: {}", e);
                return HttpResponse::InternalServerError().json(DeviceTokenResponse {
                    access_token: None,
                    token_type: None,
                    error: Some("internal_server_error".to_string()),
                });
            }

            HttpResponse::Ok().json(DeviceTokenResponse {
                access_token: Some(access_token),
                token_type: Some("Bearer".to_string()),
                error: None,
            })
        }
        None => {
            error!("Invalid device code '{}'.", req.device_code);
            HttpResponse::BadRequest().json(DeviceTokenResponse {
                access_token: None,
                token_type: None,
                error: Some("invalid_request".to_string()),
            })
        }
    }
}

use std::env;

/*
You can load the configuration values (like verification_uri, expires_in, and interval) from environment variables or a configuration file.
*/

fn load_device_flow_config() -> DeviceFlowConfig {
    let verification_uri = env::var("VERIFICATION_URI")
        .unwrap_or_else(|_| "https://yourdomain.com/device".to_string());
    let expires_in = env::var("EXPIRES_IN")
        .unwrap_or_else(|_| "600".to_string())
        .parse()
        .unwrap_or(600);
    let interval = env::var("INTERVAL")
        .unwrap_or_else(|_| "5".to_string())
        .parse()
        .unwrap_or(5);

    DeviceFlowConfig {
        verification_uri,
        expires_in,
        interval,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_device_authorization_success() {
        let store = web::Data::new(DeviceCodeStore::new());

        // Create a mock config for the test
        let device_flow_config = web::Data::new(DeviceFlowConfig {
            verification_uri: "https://test-domain.com/device".to_string(),
            expires_in: 600,
            interval: 5,
        });

        let req_body = DeviceAuthorizationRequest {
            client_id: "test_client_id".to_string(),
            scope: None, // Add scope field
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(device_flow_config.clone()) // Add mock config
                .route(
                    "/device_authorize",
                    web::post().to(device_authorization_endpoint),
                ),
        )
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
        assert_eq!(resp_body.verification_uri, "https://test-domain.com/device");
        // Validate the verification_uri
    }

    // New test: Ensure tokens are not issued for expired device codes
    #[actix_web::test]
    async fn test_device_token_expired_code() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());
        let rate_limiter = web::Data::new(RateLimiter::new(10, Duration::from_secs(60)));

        // Add an expired device code
        store.store_device_code(DeviceCode {
            device_code: "expired_device_code".to_string(),
            user_code: "user123".to_string(),
            client_id: "client123".to_string(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 10, // Expired 10 seconds ago
            authorized: true,
            scopes: Some("read write".to_string()), // Requested scopes
        });

        let req_body = DeviceTokenRequest {
            client_id: "client123".to_string(),
            device_code: "expired_device_code".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(token_store.clone())
                .app_data(rate_limiter.clone())
                .route("/device_token", web::post().to(device_token_endpoint)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/device_token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // Token request should fail due to expired code

        let resp_body: DeviceTokenResponse = test::read_body_json(resp).await;
        assert_eq!(resp_body.error.unwrap(), "expired_token");
    }

    // New test: Ensure invalid device codes return an error in polling request
    #[actix_web::test]
    async fn test_invalid_device_code_in_polling_request() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());
        let rate_limiter = web::Data::new(RateLimiter::new(10, Duration::from_secs(60)));

        let req_body = DeviceTokenRequest {
            client_id: "client123".to_string(),
            device_code: "invalid_device_code".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(token_store.clone())
                .app_data(rate_limiter.clone())
                .route("/device_token", web::post().to(device_token_endpoint)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/device_token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // Invalid device code should result in error

        let resp_body: DeviceTokenResponse = test::read_body_json(resp).await;
        assert_eq!(resp_body.error.unwrap(), "invalid_request");
    }

    // New test: Ensure token is issued only for authorized devices
    #[actix_web::test]
    async fn test_token_issued_for_authorized_devices_only() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());
        let rate_limiter = web::Data::new(RateLimiter::new(10, Duration::from_secs(60)));

        // Add a non-authorized device code
        store.store_device_code(DeviceCode {
            device_code: "unauthorized_device_code".to_string(),
            user_code: "user123".to_string(),
            client_id: "client123".to_string(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600, // Expires in 10 minutes
            authorized: false,                      // Not yet authorized
            scopes: Some("read write".to_string()), // Requested scopes
        });

        let req_body = DeviceTokenRequest {
            client_id: "client123".to_string(),
            device_code: "unauthorized_device_code".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(token_store.clone())
                .app_data(rate_limiter.clone())
                .route("/device_token", web::post().to(device_token_endpoint)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/device_token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // Token request should fail since device is not authorized

        let resp_body: DeviceTokenResponse = test::read_body_json(resp).await;
        assert_eq!(resp_body.error.unwrap(), "authorization_pending");
    }

    // Test to ensure that tokens are issued after authorization
    #[actix_web::test]
    async fn test_token_issued_after_authorization() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());
        let rate_limiter = web::Data::new(RateLimiter::new(10, Duration::from_secs(60)));

        // Add an authorized device code
        store.store_device_code(DeviceCode {
            device_code: "authorized_device_code".to_string(),
            user_code: "user123".to_string(),
            client_id: "client123".to_string(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600, // Expires in 10 minutes
            authorized: true,                       // Device has been authorized
            scopes: Some("read write".to_string()), // Requested scopes
        });

        let req_body = DeviceTokenRequest {
            client_id: "client123".to_string(),
            device_code: "authorized_device_code".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(token_store.clone())
                .app_data(rate_limiter.clone())
                .route("/device_token", web::post().to(device_token_endpoint)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/device_token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200); // Token should be issued successfully

        let resp_body: DeviceTokenResponse = test::read_body_json(resp).await;
        assert!(resp_body.access_token.is_some());
    }

    #[actix_web::test]
    async fn test_rate_limiter_allows_requests_within_limit() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());

        // Initialize RateLimiter with a limit of 3 requests per minute
        let rate_limiter = web::Data::new(RateLimiter::new(3, Duration::from_secs(60)));

        // Add a valid device code
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
            scopes: Some("read write".to_string()),
        });

        let req_body = DeviceTokenRequest {
            client_id: "client123".to_string(),
            device_code: "test_device_code".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(token_store.clone())
                .app_data(rate_limiter.clone())
                .route("/device_token", web::post().to(device_token_endpoint)),
        )
        .await;

        // Make 3 requests within the limit
        for _ in 0..3 {
            let req = test::TestRequest::post()
                .uri("/device_token")
                .set_json(&req_body)
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
        }
    }

    #[actix_web::test]
    async fn test_rate_limiter_exceeds_limit() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());

        // Initialize RateLimiter with a limit of 3 requests per minute
        let rate_limiter = web::Data::new(RateLimiter::new(3, Duration::from_secs(60)));

        // Add a valid device code
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
            scopes: Some("read write".to_string()),
        });

        let req_body = DeviceTokenRequest {
            client_id: "client123".to_string(),
            device_code: "test_device_code".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(token_store.clone())
                .app_data(rate_limiter.clone())
                .route("/device_token", web::post().to(device_token_endpoint)),
        )
        .await;

        // Make 3 requests within the limit
        for _ in 0..3 {
            let req = test::TestRequest::post()
                .uri("/device_token")
                .set_json(&req_body)
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
        }

        // Make 4th request (should be rate-limited)
        let req = test::TestRequest::post()
            .uri("/device_token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 429); // Expecting 429 Too Many Requests
    }

    #[actix_web::test]
    async fn test_rate_limiter_resets_after_window() {
        let store = web::Data::new(DeviceCodeStore::new());
        let token_store = web::Data::new(InMemoryTokenStore::new());

        // Initialize RateLimiter with a limit of 3 requests per minute
        let rate_limiter = web::Data::new(RateLimiter::new(3, Duration::from_secs(2))); // 2 seconds window

        // Add a valid device code
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
            scopes: Some("read write".to_string()),
        });

        let req_body = DeviceTokenRequest {
            client_id: "client123".to_string(),
            device_code: "test_device_code".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(store.clone())
                .app_data(token_store.clone())
                .app_data(rate_limiter.clone())
                .route("/device_token", web::post().to(device_token_endpoint)),
        )
        .await;

        // Make 3 requests within the limit
        for _ in 0..3 {
            let req = test::TestRequest::post()
                .uri("/device_token")
                .set_json(&req_body)
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
        }

        // Wait for the rate limit window to reset
        actix_web::rt::time::sleep(Duration::from_secs(3)).await; // Wait for 3 seconds to exceed window

        // Now the rate limiter should reset, and the next request should succeed
        let req = test::TestRequest::post()
            .uri("/device_token")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200); // This request should pass after the reset
    }
}
