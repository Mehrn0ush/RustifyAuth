use base64::{engine::general_purpose::URL_SAFE, Engine};
use rand::Rng;
use sha2::{Digest, Sha256};

const CODE_VERIFIER_MIN_LENGTH: usize = 43;
const CODE_VERIFIER_MAX_LENGTH: usize = 128;

#[derive(Debug, PartialEq)]
pub enum PkceMethod {
    Plain,
    S256,
}

impl PkceMethod {
    pub fn from_str(method: &str) -> Option<PkceMethod> {
        match method {
            "plain" => Some(PkceMethod::Plain),
            "S256" => Some(PkceMethod::S256),
            _ => None,
        }
    }
}

pub fn generate_code_verifier() -> String {
    let verifier_length =
        rand::thread_rng().gen_range(CODE_VERIFIER_MIN_LENGTH..=CODE_VERIFIER_MAX_LENGTH);
    let verifier: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(verifier_length)
        .map(char::from)
        .collect();
    verifier
}

pub fn generate_code_challenge(verifier: &str, method: PkceMethod) -> String {
    match method {
        PkceMethod::Plain => verifier.to_string(),
        PkceMethod::S256 => {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let hash = hasher.finalize();
            URL_SAFE.encode(&hash)
        }
    }
}

pub fn validate_pkce(
    code_challenge: &Option<String>,
    code_challenge_method: &Option<String>,
    verifier: &str,
) -> bool {
    if verifier.len() < CODE_VERIFIER_MIN_LENGTH {
        return false; // Fail if the verifier is too short
    }

    if code_challenge.is_none() || code_challenge_method.is_none() {
        return false;
    }

    let method = code_challenge_method.as_deref().unwrap_or("");

    match method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let hashed = hasher.finalize();
            let code_challenge_computed = URL_SAFE.encode(&hashed);
            code_challenge
                .as_ref()
                .map(|cc| *cc == code_challenge_computed)
                .unwrap_or(false)
        }
        "plain" => code_challenge
            .as_ref()
            .map(|cc| *cc == verifier)
            .unwrap_or(false),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_challenge_plain() {
        let verifier = "exampleverifier123456789012345678901234567890123456".to_string(); // 43 chars
        let challenge = generate_code_challenge(&verifier, PkceMethod::Plain);
        assert_eq!(challenge, verifier);
    }

    #[test]
    fn test_validate_pkce_plain() {
        let verifier = "exampleverifier123456789012345678901234567890123456".to_string(); // 43 chars
        let challenge = generate_code_challenge(&verifier, PkceMethod::Plain);
        let is_valid = validate_pkce(&Some(challenge), &Some("plain".to_string()), &verifier);
        assert!(
            is_valid,
            "Validation should pass for the correct plain challenge."
        );
    }

    #[test]
    fn test_validate_pkce_s256() {
        let verifier = "exampleverifier123456789012345678901234567890123456"; // 43 chars
        let challenge = generate_code_challenge(&verifier, PkceMethod::S256);
        let expected_challenge = "Og-h1KL_BMLt8XWNUYYDeUU12LvjWk58Ue8cYNza_Bg=";
        assert_eq!(challenge, expected_challenge);
        let is_valid = validate_pkce(
            &Some(challenge.clone()),
            &Some("S256".to_string()),
            &verifier,
        );
        assert!(
            is_valid,
            "Validation should pass for the correct S256 challenge."
        );
    }

    #[test]
    fn test_invalid_pkce() {
        let verifier = "invalidverifier123456789012345678901234567890123456".to_string(); // 43 chars
        let challenge = "wfp4Z3Vkc3QqLNd0M9XYGgEZ_5mpeYvAqEby3gUx-5I".to_string();
        let is_valid = validate_pkce(&Some(challenge), &Some("S256".to_string()), &verifier);
        assert!(
            !is_valid,
            "Validation should fail for an incorrect S256 challenge."
        );
    }

    #[test]
    fn test_generate_code_verifier_with_plain() {
        let verifier = "exampleverifier123456789012345678901234567890123456".to_string(); // 43 chars
        let challenge = generate_code_challenge(&verifier, PkceMethod::Plain);
        let is_valid = validate_pkce(
            &Some(challenge.clone()),
            &Some("plain".to_string()),
            &verifier,
        );
        assert!(is_valid, "Validation should pass for plain challenge.");
    }

    #[test]
    fn test_invalid_code_verifier_length() {
        let short_verifier = "shortverifier".to_string(); // <43 chars
        let challenge = generate_code_challenge(&short_verifier, PkceMethod::Plain);
        // Even if challenge equals verifier, validation should fail due to short length
        let is_valid = validate_pkce(
            &Some(challenge),
            &Some("plain".to_string()),
            &short_verifier,
        );
        assert!(!is_valid, "Validation should fail for a short verifier.");
    }

    #[test]
    fn test_generate_code_challenge_s256_correct() {
        let verifier = "exampleverifier123456789012345678901234567890123456"; // 43 chars
        let challenge = generate_code_challenge(&verifier, PkceMethod::S256);
        let expected_challenge = "Og-h1KL_BMLt8XWNUYYDeUU12LvjWk58Ue8cYNza_Bg=";
        assert_eq!(challenge, expected_challenge);
    }
}
