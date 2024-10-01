use reqwest::Client;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
struct JWKS {
    keys: Vec<JWK>,
}

#[derive(Deserialize, Debug)]
struct JWK {
    kid: String,
    n: String,
    e: String,
}

pub async fn get_google_jwks() -> JWKS {
    let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
    let client = Client::new();
    let jwks_res = client.get(jwks_url).send().await.unwrap();
    jwks_res.json().await.unwrap()
}

pub async fn validate_google_token(id_token: &str) -> Result<serde_json::Value, String> {
    let jwks = get_google_jwks().await;
    let header = decode_header(id_token).map_err(|e| e.to_string())?;
    let kid = header.kid.ok_or("No `kid` found in token header")?;

    let jwk = jwks.keys.iter().find(|jwk| jwk.kid == kid)
        .ok_or("No matching key found for `kid`")?;

    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| e.to_string())?;

    let validation = Validation {
        algorithms: vec![Algorithm::RS256],
        ..Default::default()
    };

    let decoded = decode::<serde_json::Value>(&id_token, &decoding_key, &validation)
        .map_err(|e| e.to_string())?;

    Ok(decoded.claims)
}
