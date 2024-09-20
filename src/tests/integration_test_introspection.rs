use crate::introspection::*;
use crate::storage::RedisTokenStore;
use crate::core::token::{JwtTokenGenerator};
use std::sync::Arc;
use redis::Client;

#[tokio::test]
async fn test_introspection_with_redis_store() {
    // Set up Redis connection for testing
    let redis_client = Client::open("redis://127.0.0.1/").unwrap();
    let token_store = Arc::new(RedisTokenStore::new(redis_client.get_connection().unwrap()));
    let token_generator = Arc::new(JwtTokenGenerator::new(/* RSA Private Key */));

    let token = "valid_jwt_token"; // Generate a real JWT token for testing
    let introspection_request = IntrospectionRequest {
        token: token.to_string(),
        token_type_hint: None,
    };

    let response = introspect_token(
        introspection_request,
        token_generator.clone(),
        token_store.clone(),
        None,
    ).await;

    assert!(response.is_ok());
    let introspection_response = response.unwrap();
    assert_eq!(introspection_response.active, true);
    assert!(introspection_response.client_id.is_some());
    assert!(introspection_response.username.is_some());
}

// Additional integration tests can go here
