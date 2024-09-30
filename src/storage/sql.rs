use super::{ClientData, StorageBackend};
use crate::error::OAuthError;
use sqlx::{Pool, Postgres, Row};
use tokio::task;

/// SQL storage backend for client credentials using `sqlx`.
pub struct SqlStorage {
    pub pool: Pool<Postgres>,
}

impl SqlStorage {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = Pool::<Postgres>::connect(database_url).await?;
        Ok(SqlStorage { pool })
    }
}

impl StorageBackend for SqlStorage {
    fn get_client_by_id(&self, client_id: &str) -> Result<Option<ClientData>, OAuthError> {
        // Use `block_in_place` to run async code synchronously
        task::block_in_place(|| {
            // Use the current Tokio runtime to block on the async function
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                // Perform the asynchronous SQL operation
                let result = sqlx::query(
                    "SELECT client_id, secret, allowed_scopes FROM clients WHERE client_id = $1",
                )
                .bind(client_id)
                .fetch_optional(&self.pool) // Await the async SQL query
                .await;

                match result {
                    Ok(Some(row)) => {
                        let client_data = ClientData {
                            client_id: row.get("client_id"),
                            secret: row.get("secret"),
                            allowed_scopes: row
                                .get::<String, _>("allowed_scopes")
                                .split(',')
                                .map(String::from)
                                .collect(),
                        };
                        Ok(Some(client_data))
                    }
                    Ok(None) => Ok(None), // Client not found
                    Err(_) => Err(OAuthError::TokenGenerationError), // Handle DB error
                }
            })
        })
    }
}
