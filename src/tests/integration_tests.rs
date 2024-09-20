use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_authorization_code_flow_with_pkce() {
    // Setup necessary objects
    let authorization_flow = setup_authorization_flow();
    let client_id = "test_client";
    let redirect_uri = "https://example.com/callback";
    let pkce_verifier = "valid_pkce_verifier";
    let pkce_challenge = generate_pkce_challenge(pkce_verifier);

    // Generate authorization code
    let authorization_code = authorization_flow.generate_authorization_code(client_id, redirect_uri, &pkce_challenge);

    // Exchange authorization code for token
    let token_response = authorization_flow.exchange_code_for_token(&authorization_code, pkce_verifier);

    // Assert that tokens were issued correctly
    assert!(token_response.is_ok());
    let token_response = token_response.unwrap();
    assert!(!token_response.access_token.is_empty());
    assert!(!token_response.refresh_token.is_empty());
}

#[tokio::test]
async fn test_refresh_token_flow() {
    // Setup necessary objects
    let authorization_flow = setup_authorization_flow();
    let client_id = "test_client";
    let user_id = "test_user";

    // Generate initial tokens
    let token_response = authorization_flow.exchange_code_for_token("valid_code", "valid_pkce_verifier").unwrap();
    let refresh_token = token_response.refresh_token.clone();

    // Use refresh token to generate new access token
    let new_token_response = authorization_flow.refresh_access_token(&refresh_token);
    assert!(new_token_response.is_ok());
    let new_token_response = new_token_response.unwrap();

    // Assert that the new access token is different from the previous one
    assert_ne!(new_token_response.access_token, token_response.access_token);
}

#[tokio::test]
async fn test_invalid_pkce_verifier() {
    // Setup necessary objects
    let authorization_flow = setup_authorization_flow();
    let client_id = "test_client";
    let redirect_uri = "https://example.com/callback";
    let pkce_verifier = "valid_pkce_verifier";
    let invalid_pkce_verifier = "invalid_pkce_verifier";
    let pkce_challenge = generate_pkce_challenge(pkce_verifier);

    // Generate authorization code
    let authorization_code = authorization_flow.generate_authorization_code(client_id, redirect_uri, &pkce_challenge);

    // Attempt to exchange authorization code with an invalid PKCE verifier
    let token_response = authorization_flow.exchange_code_for_token(&authorization_code, invalid_pkce_verifier);

    // Assert that the exchange fails due to invalid PKCE verifier
    assert!(token_response.is_err());
    if let Err(e) = token_response {
        assert_eq!(e, AuthorizationError::InvalidPKCE);
    }
}

#[tokio::test]
async fn test_token_revocation() {
    // Setup necessary objects
    let mut token_store = setup_token_store();
    let token_generator = setup_token_generator();
    let client_id = "test_client";
    let user_id = "test_user";

    // Generate an access token
    let access_token = token_generator.generate_access_token(client_id, user_id);
    assert!(!access_token.is_empty());

    // Revoke the access token
    token_store.revoke_access_token(&access_token);
    assert!(token_store.is_token_revoked(&access_token));

    // Simulate checking the token in an endpoint that requires a valid token
    let is_valid = token_store.is_token_revoked(&access_token);
    assert!(is_valid, "Token should be revoked");

    // Wait for a few seconds to simulate revocation delay if necessary
    sleep(Duration::from_secs(2)).await;

    // Attempt to use revoked token should fail
    let token_check = token_store.is_token_revoked(&access_token);
    assert!(token_check, "Revoked token should not be valid");
}

#[tokio::test]
async fn test_revoked_refresh_token() {
    // Setup necessary objects
    let mut token_store = setup_token_store();
    let token_generator = setup_token_generator();
    let client_id = "test_client";
    let user_id = "test_user";

    // Generate a refresh token
    let refresh_token = token_generator.generate_refresh_token(client_id, user_id);
    assert!(!refresh_token.is_empty());

    // Revoke the refresh token
    token_store.revoke_refresh_token(&refresh_token);
    assert!(token_store.is_token_revoked(&refresh_token));

    // Attempt to use revoked refresh token should fail
    let is_valid = token_store.is_token_revoked(&refresh_token);
    assert!(is_valid, "Revoked refresh token should not be valid");
}
