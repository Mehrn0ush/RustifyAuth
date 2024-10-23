use crate::authentication::{AuthError, SessionManager, User, UserAuthenticator};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct MockUserAuthenticator {
    users: Arc<Mutex<HashMap<String, String>>>, // username -> password
}

impl MockUserAuthenticator {
    pub fn new() -> Self {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), "password123".to_string());
        users.insert("bob".to_string(), "securepassword".to_string());
        Self {
            users: Arc::new(Mutex::new(users)),
        }
    }
}

#[async_trait]
impl UserAuthenticator for MockUserAuthenticator {
    async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError> {
        let users = self.users.lock().await;
        match users.get(username) {
            Some(stored_password) if stored_password == password => Ok(User {
                id: Uuid::new_v4().to_string(),
                username: username.to_string(),
            }),
            _ => Err(AuthError::InvalidCredentials),
        }
    }

    async fn is_authenticated(&self, session_id: &str) -> Result<User, AuthError> {
        // For the mock, we'll assume any non-empty session_id is valid
        if !session_id.is_empty() {
            Ok(User {
                id: Uuid::new_v4().to_string(),
                username: "mock_user".to_string(),
            })
        } else {
            Err(AuthError::SessionNotFound)
        }
    }
}

pub struct MockSessionManager {
    sessions: Mutex<HashMap<String, User>>,
}

impl MockSessionManager {
    pub fn new() -> Self {
        MockSessionManager {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub async fn add_session(&self, session_id: &str, user: User) {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session_id.to_string(), user);
    }
}

#[async_trait]
impl SessionManager for MockSessionManager {
    async fn create_session(&self, user: &User) -> Result<String, AuthError> {
        let session_id = Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session_id.clone(), user.clone());
        Ok(session_id)
    }

    async fn get_user_by_session(&self, session_id: &str) -> Result<User, AuthError> {
        let sessions = self.sessions.lock().await;
        match sessions.get(session_id) {
            Some(user) => Ok(user.clone()),
            None => Err(AuthError::SessionNotFound),
        }
    }

    async fn destroy_session(&self, session_id: &str) -> Result<(), AuthError> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(session_id);
        Ok(())
    }
}

/*
Notes:

- The `MockUserAuthenticator` provides an in-memory user authentication mechanism.
- The `MockSessionManager` manages user sessions in memory.
- These implementations are useful for testing or as examples.
*/
