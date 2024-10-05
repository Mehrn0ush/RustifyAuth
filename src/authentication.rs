use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Trait for user authentication
#[async_trait]
pub trait UserAuthenticator: Send + Sync {
    /// Authenticate the user with given credentials
    async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError>;

    /// Check if the user is authenticated (e.g., via a session token)
    async fn is_authenticated(&self, session_id: &str) -> Result<User, AuthError>;
}

/// Trait for session management
#[async_trait]
pub trait SessionManager: Send + Sync {
    /// Create a new session for a user
    async fn create_session(&self, user: &User) -> Result<String, AuthError>;

    /// Retrieve a user by session ID
    async fn get_user_by_session(&self, session_id: &str) -> Result<User, AuthError>;

    /// Destroy a session
    async fn destroy_session(&self, session_id: &str) -> Result<(), AuthError>;
}

/// Represents a user in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    // Additional fields as needed
}

/// Error type for authentication-related errors
#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidCredentials,
    SessionNotFound,
    InternalError,
    OAuthErrorResponse
    // Add other error variants as needed
}

/*
Notes:

We use async_trait to allow asynchronous trait methods.
The UserAuthenticator trait defines methods for authenticating users and checking authentication status.
The SessionManager trait defines methods for managing user sessions.
The User struct represents a user in the system.


*/
