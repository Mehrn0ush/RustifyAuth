pub fn validate_google_claims(claims: &serde_json::Value) -> Result<(), String> {
    let aud = claims["aud"].as_str().ok_or("Missing `aud` claim")?;
    let iss = claims["iss"].as_str().ok_or("Missing `iss` claim")?;
    let exp = claims["exp"].as_i64().ok_or("Missing `exp` claim")?;
    
    if aud != std::env::var("GOOGLE_CLIENT_ID").unwrap() {
        return Err("Invalid audience".to_string());
    }

    if iss != "https://accounts.google.com" {
        return Err("Invalid issuer".to_string());
    }

    let current_time = chrono::Utc::now().timestamp();
    if exp < current_time {
        return Err("ID token expired".to_string());
    }

    Ok(())
}
