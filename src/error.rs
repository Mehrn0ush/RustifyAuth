#[derive(Debug)]
pub enum TokenError {
    InvalidToken,
    TokenRevoked,
    // Add relevant errors for token revocation
}

#[derive(Debug, PartialEq)] // Add PartialEq here
pub enum OAuthError {
    InvalidClient,
    InvalidScope,
    TokenGenerationError,
    // Add more errors as needed
}
