use actix_web_httpauth::extractors::bearer::BearerAuth;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;
use bcrypt::{hash, DEFAULT_COST};
use chrono::Utc;


#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ClientMetadata {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub software_statement: Option<String>,  // Optional JWT field
}

#[derive(Serialize, Debug, Clone)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone)]
pub struct ClientStore {
    pub clients: Mutex<HashMap<String, ClientMetadata>>, // Store client metadata securely
    pub client_secrets: Mutex<HashMap<String, String>>,  // Store client secrets securely (hashed)
}

impl ClientStore {
    pub fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            client_secrets: Mutex::new(HashMap::new()),
        }
    }

    // Register client and store metadata and secret
    pub fn register_client(
        &self,
        metadata: ClientMetadata,
    ) -> Result<ClientRegistrationResponse, &'static str> {
        let client_id = Uuid::new_v4().to_string();
        let client_secret = Uuid::new_v4().to_string();

        // Hash the client_secret before storing it
        let hashed_secret = hash(&client_secret, DEFAULT_COST).map_err(|_| "hashing_error")?;

        {
            let mut clients = self.clients.lock().unwrap();
            clients.insert(client_id.clone(), metadata);
        }

        {
            let mut secrets = self.client_secrets.lock().unwrap();
            secrets.insert(client_id.clone(), hashed_secret);
        }

        Ok(ClientRegistrationResponse {
            client_id,
            client_secret,
        })
    }
}




// The /register endpoint
async fn register_client(
    client_store: web::Data<ClientStore>,
    metadata: web::Json<ClientMetadata>,
) -> impl Responder {
    // Validate metadata
    if metadata.redirect_uris.is_empty() {
        return HttpResponse::BadRequest().body("redirect_uris is required");
    }

    if metadata.grant_types.is_empty() {
        return HttpResponse::BadRequest().body("grant_types is required");
    }

    if metadata.response_types.is_empty() {
        return HttpResponse::BadRequest().body("response_types is required");
    }

    // Validate the software statement if provided
    if let Some(software_statement) = &metadata.software_statement {
        if let Err(_) = validate_software_statement(software_statement) {
            return HttpResponse::BadRequest().body("Invalid software statement");
        }
    }

    // Register the client
    match client_store.register_client(metadata.into_inner()) {
        Ok(response) => {
            log_registration_attempt(true, &metadata);
            HttpResponse::Ok().json(response)
        }
        Err(_) => {
            log_registration_attempt(false, &metadata);
            HttpResponse::InternalServerError().body("Failed to register client")
        }
    }
}

// Log the registration attempt
pub fn log_registration_attempt(success: bool, metadata: &ClientMetadata) {
    if success {
        println!("Client registered successfully: {:?}", metadata);
    } else {
        println!("Failed registration attempt: {:?}", metadata);
    }
}

// Update client metadata
async fn update_client(
    client_store: web::Data<ClientStore>,
    client_id: web::Path<String>,
    updated_metadata: web::Json<ClientMetadata>,
) -> impl Responder {
    let mut clients = client_store.clients.lock().unwrap();

    if let Some(existing_client) = clients.get_mut(&client_id.into_inner()) {
        // Update the client metadata
        *existing_client = updated_metadata.into_inner();
        return HttpResponse::Ok().body("Client updated");
    }

    HttpResponse::NotFound().body("Client not found")
}

pub fn log_registration_attempt(success: bool, metadata: &ClientMetadata) {
    let timestamp = Utc::now().to_rfc3339();
    if success {
        println!("[INFO] [{}] Client registered successfully: {:?}", timestamp, metadata);
    } else {
        println!("[ERROR] [{}] Failed registration attempt: {:?}", timestamp, metadata);
    }
}
