use chrono::{Duration, Utc};
use rustify_auth::storage::postgres::PostgresBackend;
use rustify_auth::storage::AsyncStorageBackend;
use rustify_auth::storage::TokenData;
use serde_json::json;
use tokio_postgres::NoTls;

#[tokio::test]
async fn test_postgres_token_storage() {
    let database_url = "postgres://rustify_auth:password@localhost:5432/rustify_auth_db";

    let (client, connection) = tokio_postgres::connect(database_url, NoTls)
        .await
        .expect("Failed to connect to Postgres for test setup");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    client
        .execute("DELETE FROM tokens WHERE client_id = $1", &[&"client123"])
        .await
        .expect("Failed to clean up tokens before test");
    client
        .execute("DELETE FROM clients WHERE client_id = $1", &[&"client123"])
        .await
        .expect("Failed to clean up client before test");
    client
        .execute(
            "INSERT INTO clients (client_id, secret, redirect_uris) VALUES ($1, $2, $3::jsonb)",
            &[&"client123", &"test_secret", &json!([]).to_string()],
        )
        .await
        .expect("Failed to insert client required by foreign key");

    // Initialize the backend connection
    let backend = PostgresBackend::new(database_url).expect("Failed to connect to Postgres");

    // Define token data for testing
    let token_data = TokenData {
        access_token: "test_access".to_string(),
        refresh_token: Some("test_refresh".to_string()),
        expires_at: Utc::now().naive_utc() + Duration::seconds(3600), // Use a real datetime
        scope: Some("read write".to_string()),
        client_id: "client123".to_string(),
    };

    // Step 1: Store the token in the database
    let store_result = backend.store_token(token_data.clone()).await;
    assert!(
        store_result.is_ok(),
        "Failed to store token: {:?}",
        store_result.err()
    );

    // Step 2: Retrieve the stored token and verify its properties
    let retrieved_token = backend.get_token(&token_data.access_token).await;
    assert!(
        retrieved_token.is_ok(),
        "Failed to retrieve token: {:?}",
        retrieved_token.err()
    );
    let retrieved_token = retrieved_token.unwrap();
    assert!(
        retrieved_token.is_some(),
        "Token not found in database after storage"
    );
    let retrieved_token = retrieved_token.unwrap();

    // Check each field of the retrieved token
    assert_eq!(
        retrieved_token.access_token, token_data.access_token,
        "Access token does not match stored value"
    );
    assert_eq!(
        retrieved_token.refresh_token, token_data.refresh_token,
        "Refresh token does not match stored value"
    );
    assert_eq!(
        retrieved_token.client_id, token_data.client_id,
        "Client ID does not match stored value"
    );
    assert_eq!(
        retrieved_token.scope, token_data.scope,
        "Scope does not match stored value"
    );

    // Step 3: Delete the token and confirm deletion was successful
    let delete_result = backend.delete_token(&token_data.access_token).await;
    assert!(
        delete_result.is_ok(),
        "Failed to delete token: {:?}",
        delete_result.err()
    );

    // Step 4: Attempt to retrieve the token after deletion to confirm it was removed
    let deleted_token = backend.get_token(&token_data.access_token).await;
    assert!(
        deleted_token.is_ok(),
        "Error occurred while retrieving token after deletion: {:?}",
        deleted_token.err()
    );
    assert!(
        deleted_token.unwrap().is_none(),
        "Token still exists in database after deletion"
    );

    client
        .execute("DELETE FROM clients WHERE client_id = $1", &[&"client123"])
        .await
        .expect("Failed to clean up client after test");
}
