pub async fn validate_google_id_token(id_token: &str) -> Result<(), String> {
    let claims = crate::oidc::jwks::validate_google_token(id_token).await?;
    crate::oidc::claims::validate_google_claims(&claims)?;
    Ok(())
}
