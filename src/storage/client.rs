use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Define a struct for Client
#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
}

// Define a trait for Client repository
pub trait ClientRepository {
    fn get_client(&self, client_id: &str) -> Option<Client>;
    fn register_client(&mut self, client: Client);
}

// Implement a simple in-memory client repository
#[derive(Default)]
pub struct InMemoryClientRepository {
    clients: Arc<Mutex<HashMap<String, Client>>>,
}

impl ClientRepository for InMemoryClientRepository {
    fn get_client(&self, client_id: &str) -> Option<Client> {
        let clients = self.clients.lock().unwrap();
        clients.get(client_id).cloned()
    }

    fn register_client(&mut self, client: Client) {
        let mut clients = self.clients.lock().unwrap();
        clients.insert(client.client_id.clone(), client);
    }
}

// Function to create a new client
pub fn new_client(
    client_id: &str,
    client_secret: &str,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
) -> Client {
    Client {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        redirect_uris,
        scopes,
    }
}
