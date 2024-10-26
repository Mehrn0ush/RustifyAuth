use serde::{Deserialize, Serialize};

use serde::de::{self, Deserializer};
use std::fmt;

fn deserialize_null_as_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrNull;

    impl<'de> de::Visitor<'de> for StringOrNull {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or null")
        }

        fn visit_str<E>(self, v: &str) -> Result<String, E>
        where
            E: de::Error,
        {
            Ok(v.to_string())
        }

        fn visit_string<E>(self, v: String) -> Result<String, E>
        where
            E: de::Error,
        {
            Ok(v)
        }

        fn visit_unit<E>(self) -> Result<String, E>
        where
            E: de::Error,
        {
            Ok(String::new())
        }

        fn visit_none<E>(self) -> Result<String, E>
        where
            E: de::Error,
        {
            Ok(String::new())
        }

        fn visit_some<D>(self, deserializer: D) -> Result<String, D::Error>
        where
            D: Deserializer<'de>,
        {
            Deserialize::deserialize(deserializer)
        }
    }

    deserializer.deserialize_any(StringOrNull)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(deserialize_with = "deserialize_null_as_empty_string")]
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Option<String>,
}

// Token error types used across modules
#[derive(Debug, PartialEq)]
pub enum TokenError {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidPKCEChallenge,
    InternalError,
    InvalidToken,
    RateLimited,
    MissingFields,
    InvalidTokenTypeHint,
    InsufficientScope,
    ExpiredToken,
    InvalidSignature,
    UnsupportedOperation,
    InvalidTokenBinding,
    MissingTokenBinding,
}

// Define TokenRequest struct (adjust fields based on your OAuth 2.0 implementation)

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub pkce_verifier: Option<String>,
    pub device_code: Option<String>, // For device flow
    pub extra_params: Option<std::collections::HashMap<String, String>>, // For extension grants
}

// Define RegistrationError for RBAC
#[derive(Debug, PartialEq)]
pub enum RegistrationError {
    UnauthorizedClient,
    InvalidRequest,
    InvalidGrant,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionMetadata {
    pub action_timestamp: String,
    pub performed_by: String,
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientDeleteResponse {
    pub message: String,
    pub metadata: ActionMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientUpdateResponse {
    pub message: String,
    pub metadata: ActionMetadata,
}
