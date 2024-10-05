use async_trait::async_trait;

pub mod mock;
pub mod rbac;


#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    // Add other user-related fields as needed
}

#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    DatabaseError,
    // Add other error variants as needed
}

#[async_trait]
pub trait SessionManager: Send + Sync {
    async fn create_session(&self, user_id: &str) -> Result<String, ()>;
    async fn get_user_by_session(&self, session_id: &str) -> Result<User, ()>;
    async fn destroy_session(&self, session_id: &str) -> Result<(), ()>;
}

#[async_trait]
pub trait UserAuthenticator: Send + Sync {
    async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError>;
}

