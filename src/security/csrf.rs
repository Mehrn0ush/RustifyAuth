use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Define a struct to hold CSRF tokens and their associated state
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CsrfToken {
    pub token: String,
    pub state: String,
}

// Store CSRF tokens in memory for demonstration purposes
pub struct CsrfStore {
    tokens: Mutex<HashMap<String, CsrfToken>>,
}

impl CsrfStore {
    pub fn new() -> Self {
        CsrfStore {
            tokens: Mutex::new(HashMap::new()),
        }
    }

    // Generate a new CSRF token and state
    pub fn generate_token(&self) -> CsrfToken {
        let mut rng = rand::thread_rng();
        let token: String = (0..32)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char) // Convert to char
            .collect();
        let state: String = (0..16)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char) // Convert to char
            .collect();

        let csrf_token = CsrfToken { token, state };

        // Store the token
        self.tokens
            .lock()
            .unwrap()
            .insert(csrf_token.token.clone(), csrf_token.clone());

        csrf_token
    }

    // Validate a given CSRF token and state
    pub fn validate(&self, token: &str, state: &str) -> bool {
        if let Some(csrf_token) = self.tokens.lock().unwrap().get(token) {
            return csrf_token.state == state;
        }
        false
    }

    // Save the CSRF state (for demonstration purposes)
    pub fn save_state(&self, state: &str) {
        // In a real application, you might store the state in a session or database
        println!("Saving state: {}", state);
    }
}

// Additional functions for external use
pub fn validate_state(store: &CsrfStore, token: &str, state: &str) -> bool {
    store.validate(token, state)
}

pub fn save_state(store: &CsrfStore, state: &str) {
    store.save_state(state)
}
