use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Trait for user authentication
#[async_trait]
pub trait UserAuthenticator: Send + Sync {
    async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError>;
    async fn is_authenticated(&self, session_id: &str) -> Result<User, AuthError>;
}

/// Trait for session management

#[async_trait]
pub trait SessionManager: Send + Sync {
    async fn create_session(&self, user: &User) -> Result<String, AuthError>;
    async fn get_user_by_session(&self, session_id: &str) -> Result<User, AuthError>;
    async fn destroy_session(&self, session_id: &str) -> Result<(), AuthError>;
}

/// Represents a user in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
}

/// Error type for authentication-related errors
#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidCredentials,
    SessionNotFound,
    InternalError,
    OAuthErrorResponse,
}

/*
Notes:

We use async_trait to allow asynchronous trait methods.
The UserAuthenticator trait defines methods for authenticating users and checking authentication status.
The SessionManager trait defines methods for managing user sessions.
The User struct represents a user in the system.


*/
