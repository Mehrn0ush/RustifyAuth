use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

pub struct RateLimiter {
    requests: Mutex<HashMap<String, (u64, SystemTime)>>, // Track requests and timestamp keyed by client ID
    max_requests: u64,                                   // Maximum allowed requests
    window_size: Duration,                               // Sliding window duration (e.g., 1 minute)
}

impl RateLimiter {
    pub fn new(max_requests: u64, window_size: Duration) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_requests,
            window_size,
        }
    }

    // Check if the client has exceeded the allowed requests in the window
    pub fn is_rate_limited(&self, client_id: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let current_time = SystemTime::now();

        if let Some((count, last_request_time)) = requests.get_mut(client_id) {
            // Calculate time since the last request
            if current_time.duration_since(*last_request_time).unwrap() > self.window_size {
                *count = 0; // Reset if outside the window
            }

            *last_request_time = current_time;

            if *count >= self.max_requests {
                return true; // Rate limit exceeded
            }

            *count += 1; // Increment count for valid requests
            false
        } else {
            // First request for this client
            requests.insert(client_id.to_string(), (1, current_time));
            false
        }
    }

    // Increment the rate limiter for failed attempts
    pub fn increment(&self, client_id: &str) {
        let mut requests = self.requests.lock().unwrap();
        if let Some((count, _)) = requests.get_mut(client_id) {
            *count += 1;
        } else {
            requests.insert(client_id.to_string(), (1, SystemTime::now()));
        }
    }
}
