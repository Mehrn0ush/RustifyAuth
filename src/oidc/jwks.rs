use crate::storage::client;
use base64::engine::general_purpose::{self, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use reqwest::Client;
use rsa::pkcs1::LineEnding;
use serde::{Deserialize, Serialize};
use std::env;


#[derive(Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}


#[derive(Deserialize, Debug)]
pub struct Jwk {
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

// Function to fetch JWKS from the provided URL
pub async fn fetch_jwks(url: Option<&str>) -> Result<Jwks, Box<dyn std::error::Error>> {
    let url = url.unwrap_or("https://www.googleapis.com/oauth2/v3/certs"); // Use mock URL in tests
    let client = Client::new();
    let response = client.get(url).send().await?;

    // Debugging print: Status and body
    println!("Response Status: {}", response.status());
    let body = response.text().await?;
    println!("Response Body: {}", body);

    let jwks: Jwks = serde_json::from_str(&body)?;
    Ok(jwks)
}

// Function to validate a Google token
pub async fn validate_google_token(
    id_token: &str,
    url: Option<&str>,
) -> Result<TokenData<Claims>, String> {
    // Fetch JWKS
    let jwks = fetch_jwks(url).await.map_err(|e| e.to_string())?;

    // Extract the `kid` from the JWT header
    let header: jsonwebtoken::Header =
        jsonwebtoken::decode_header(id_token).map_err(|_| "Invalid token header".to_string())?;

    let kid = header.kid.ok_or("Missing kid in token header")?;
    println!("Kid extracted from token: {}", kid);

    // Find the corresponding JWK
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or("No matching JWK found")?;

    println!("Found JWK: {:?}", jwk);
    println!("Expected n: {}", &jwk.n);
    println!("Expected e: {}", &jwk.e);

    // Create a DecodingKey from the JWK
    let decoding_key = DecodingKey::from_rsa_components(
        &jwk.n, // Use the base64 encoded string directly
        &jwk.e, // Use the base64 encoded string directly
    )
    .map_err(|e| {
        println!("Error creating DecodingKey: {}", e);
        e.to_string()
    })?;

    // Validate the token
    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<Claims>(id_token, &decoding_key, &validation).map_err(|e| {
        println!("Error validating token: {}", e);
        e.to_string()
    })?;

    Ok(token_data)
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
    pub aud: String,
    pub iss: String,
}

pub fn create_test_token_with_key(
    claims: &Claims,
    encoding_key: &EncodingKey,
    kid: &str,
) -> Result<String, String> {
    // Create the JWT header with the correct `kid`
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());

    // Encode the token
    let token = encode(&header, claims, encoding_key).map_err(|e| e.to_string())?;
    println!("Generated Token: {}", token);

    Ok(token)
}

// Function to get the current timestamp
fn get_current_timestamp() -> usize {
    chrono::Utc::now().timestamp() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hex;
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_validate_google_token() {
        // Step 1: Generate RSA key pair
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        // Step 2: Extract modulus (n) and exponent (e) from public key
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();

        // Base64 URL-safe encoding without padding
        let n_b64 = URL_SAFE_NO_PAD.encode(&n);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e);

        // Define a unique Key ID (kid)
        let kid = "test-kid-12345";

        // Step 3: Mock JWKS with the public key
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/oauth2/v3/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "kid": kid,
                        "n": n_b64,
                        "e": e_b64,
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        // Step 4: Create valid claims for the token
        let claims = Claims {
            sub: "1234567890".to_string(),
            email: "test@example.com".to_string(),
            exp: get_current_timestamp() + 3600,
            aud: "your_audience".to_string(),
            iss: "https://accounts.google.com".to_string(),
        };

        // Step 5: Create the JWT token using the private key
        let token = {
            // Convert RSA private key to PEM format
            let private_key_pem = private_key
                .to_pkcs1_pem(LineEnding::LF)
                .map_err(|e| e.to_string())
                .expect("Failed to convert private key to PEM");

            // Create EncodingKey from the private key PEM
            let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
                .expect("Failed to create encoding key");

            // Create JWT header with the correct `kid`
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(kid.to_string());

            // Encode the token
            encode(&header, &claims, &encoding_key).expect("Failed to encode token");
            // Create JWT token with the correct `kid`
            create_test_token_with_key(&claims, &encoding_key, kid)
                .expect("Failed to create test token")
        };

        // Log the generated token and keys for debugging
        println!("Generated Token: {}", token);
        println!("Modulus (n): {}", n_b64);
        println!("Exponent (e): {}", e_b64);

        // Step 6: Validate the token using the mocked JWKS URL
        let jwks_url = format!("{}/oauth2/v3/certs", &mock_server.uri());
        let result = validate_google_token(&token, Some(&jwks_url)).await;

        // Step 7: Assert that validation is successful
        assert!(
            result.is_ok(),
            "Expected valid token validation, but received an error: {:?}",
            result.err()
        );

        // Optionally, assert the contents of the claims
        if let Ok(token_data) = result {
            assert_eq!(token_data.claims.sub, "1234567890");
            assert_eq!(token_data.claims.email, "test@example.com");
            assert_eq!(token_data.claims.aud, "your_audience");
            assert_eq!(token_data.claims.iss, "https://accounts.google.com");
        }
    }
}
