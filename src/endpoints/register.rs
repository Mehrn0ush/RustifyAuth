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


async fn rbac_check(token: &str, required_role: &str) -> Result<(), &'static str> {
    let claims = validate_jwt(token)?;
    if claims.role != required_role {
        return Err("Unauthorized: insufficient role.");
    }
    Ok(())
}
    // Register client and store metadata and secret
    async fn register_client(
        client_store: web::Data<ClientStore>,
        metadata: web::Json<ClientMetadata>,
        credentials: BearerAuth,    
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


pub fn validate_software_statement(jwt: &str) -> Result<TokenData<Claims>, Error> {
    let decoding_key = DecodingKey::from_secret("your_secret".as_ref());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;  // Ensure the expiration is validated
    
    decode::<Claims>(jwt, &decoding_key, &validation)
}


// The /register endpoint
async fn register_client(
    client_store: web::Data<ClientStore>,
    metadata: web::Json<ClientMetadata>,
    credentials: BearerAuth,

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
        log_registration_update(true, existing_client);
        return HttpResponse::Ok().body("Client updated");
    }
    log_registration_update(false, &updated_metadata.into_inner());
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
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn test_register_client_success() {
        let store = web::Data::new(ClientStore::new());
        let metadata = ClientMetadata {
            client_name: "Test Client".to_string(),
            redirect_uris: vec!["http://localhost/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            software_statement: None,
        };

        let app = test::init_service(App::new().app_data(store.clone()).route("/register", web::post().to(register_client))).await;

        let req = test::TestRequest::post().uri("/register").set_json(&metadata).to_request();
        let resp: ClientRegistrationResponse = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.client_id.is_empty());
        assert!(!resp.client_secret.is_empty());
    }
}

// The /update endpoint for updating client metadata
async fn update_client(
    client_store: web::Data<ClientStore>,
    client_id: web::Path<String>,
    updated_metadata: web::Json<ClientMetadata>,
) -> impl Responder {
    let mut clients = client_store.clients.lock().unwrap();

    if let Some(existing_client) = clients.get_mut(&client_id.into_inner()) {
        // Update the client metadata
        *existing_client = updated_metadata.into_inner();
        log_registration_update(true, existing_client);
        return HttpResponse::Ok().body("Client updated successfully.");
    }

    log_registration_update(false, &updated_metadata.into_inner());
    HttpResponse::NotFound().body("Client not found")
}

// Log the update attempt
pub fn log_registration_update(success: bool, metadata: &ClientMetadata) {
    if success {
        println!("Client updated successfully: {:?}", metadata);
    } else {
        println!("Failed update attempt: {:?}", metadata);
    }
}


// Logging successful or failed client registrations
pub fn log_registration_attempt(success: bool, metadata: &ClientMetadata) {
    if success {
        println!("Client registered successfully: {:?}", metadata);
    } else {
        println!("Failed registration attempt: {:?}", metadata);
    }
}

// Comprehensive logging including client ID and timestamp
pub fn log_audit_event(event_type: &str, client_id: &str, metadata: &ClientMetadata) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    println!(
        "{} event at {}: Client ID: {}, Metadata: {:?}",
        event_type, timestamp, client_id, metadata
    );
}
