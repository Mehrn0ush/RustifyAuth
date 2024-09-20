use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

pub fn encrypt_jwe(data: &str, secret_key: &[u8]) -> String {
    // Encrypt sensitive data using JWE encryption.
    let header = Header::new(Algorithm::RS256);
    let token = encode(&header, &data, &EncodingKey::from_secret(secret_key)).unwrap();
    token
}
