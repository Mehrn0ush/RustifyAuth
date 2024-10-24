use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use constant_time_eq::constant_time_eq;
use sha2::{Digest, Sha256};
use thiserror::Error; // For better error handling

// Define the minimum PKCE verifier length according to the OAuth 2.1 spec
const MIN_VERIFIER_LENGTH: usize = 43;
const MAX_VERIFIER_LENGTH: usize = 128;

#[derive(Error, Debug, PartialEq)]
pub enum PkceError {
    #[error("Verifier is too short or too long")]
    InvalidVerifierLength,
    #[error("Invalid characters in verifier")]
    InvalidVerifierCharacters,
    #[error("PKCE challenge does not match the verifier")]
    InvalidVerifier, // Add a descriptive error message here
}

// Function to validate if a PKCE verifier meets the length and character requirements
fn validate_verifier(verifier: &str) -> Result<(), PkceError> {
    // Check that the verifier contains only valid characters (alphanumeric and "-._~")
    if !verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
    {
        return Err(PkceError::InvalidVerifierCharacters);
    }

    // Check that the verifier length is within the allowed range (43-128 characters)
    if verifier.len() < MIN_VERIFIER_LENGTH || verifier.len() > MAX_VERIFIER_LENGTH {
        return Err(PkceError::InvalidVerifierLength);
    }

    Ok(())
}

// Function to generate the PKCE challenge from the verifier using SHA256 and Base64URL encoding
pub fn generate_pkce_challenge(verifier: &str) -> Result<String, PkceError> {
    // First, validate the verifier
    validate_verifier(verifier)?;

    // Step 1: Hash the verifier using SHA256
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();

    // Step 2: Encode the hash using Base64URL encoding (without padding)
    Ok(URL_SAFE_NO_PAD.encode(&hash))
}

// Function to validate the PKCE challenge by comparing the hashed verifier with the stored challenge

pub fn validate_pkce_challenge(challenge: &str, verifier: &str) -> Result<(), PkceError> {
    validate_verifier(verifier)?;
    let generated_challenge = generate_pkce_challenge(verifier)?;
    eprintln!("Stored challenge: {}", challenge);
    eprintln!("Generated challenge: {}", generated_challenge);
    if constant_time_eq::constant_time_eq(challenge.as_bytes(), generated_challenge.as_bytes()) {
        Ok(())
    } else {
        Err(PkceError::InvalidVerifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_pkce_verifier() {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = generate_pkce_challenge(verifier);
        assert!(challenge.is_ok());
    }

    #[test]
    fn test_invalid_pkce_verifier_length() {
        let short_verifier = "short";
        let long_verifier = "a".repeat(200); // Over the max length

        let short_result = generate_pkce_challenge(&short_verifier);
        let long_result = generate_pkce_challenge(&long_verifier);

        assert_eq!(short_result.unwrap_err(), PkceError::InvalidVerifierLength);
        assert_eq!(long_result.unwrap_err(), PkceError::InvalidVerifierLength);
    }

    #[test]
    fn test_invalid_pkce_verifier_characters() {
        let invalid_verifier = "invalid@chars!";
        let result = generate_pkce_challenge(invalid_verifier);
        assert_eq!(result.unwrap_err(), PkceError::InvalidVerifierCharacters);
    }

    #[test]
    fn test_valid_pkce_challenge_validation() {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = generate_pkce_challenge(verifier).unwrap();

        let result = validate_pkce_challenge(&challenge, verifier);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_pkce_challenge_validation() {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = generate_pkce_challenge(verifier).unwrap();

        let result = validate_pkce_challenge("incorrect_challenge", verifier);
        assert_eq!(result.unwrap_err(), PkceError::InvalidVerifier);
    }
}
