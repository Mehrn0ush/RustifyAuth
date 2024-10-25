use crate::error::OAuthError;
use crate::storage::{AsyncStorageBackend, ClientData, StorageBackend, TokenData};
use async_trait::async_trait;
use chrono::NaiveDateTime;
use chrono::{DateTime, Utc};
use deadpool_postgres::{Client, Manager, ManagerConfig, Pool, RecyclingMethod};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::runtime::Runtime;
use tokio_postgres::NoTls;

pub struct PostgresBackend {
    pool: Pool,
}

impl PostgresBackend {
    pub fn new(db_url: &str) -> Result<Self, OAuthError> {
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let manager = Manager::new(
            db_url.parse().map_err(|_| OAuthError::DatabaseError)?,
            NoTls,
        );
        let pool = Pool::builder(manager)
            .max_size(16)
            .build()
            .map_err(|_| OAuthError::DatabaseError)?;
        Ok(Self { pool })
    }

    async fn get_client(&self) -> Result<Client, OAuthError> {
        self.pool.get().await.map_err(|_| OAuthError::DatabaseError)
    }
}

// Async implementation for `AsyncStorageBackend`
#[async_trait]
impl AsyncStorageBackend for PostgresBackend {
    async fn store_token(&self, token_data: TokenData) -> Result<(), OAuthError> {
        let client = self.get_client().await?;

        // Convert `NaiveDateTime` to `SystemTime` for PostgreSQL compatibility
        let expires_at_system_time: SystemTime = SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(
                token_data.expires_at.timestamp() as u64,
            ))
            .ok_or(OAuthError::DatabaseError)?;

        client
            .execute(
                "INSERT INTO tokens (access_token, refresh_token, expires_at, scope, client_id, token_type) 
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (access_token) DO NOTHING",
                &[
                    &token_data.access_token,
                    &token_data.refresh_token,
                    &expires_at_system_time,
                    &token_data.scope,
                    &token_data.client_id,
                    &"Bearer".to_string(),
                ],
            )
            .await
            .map_err(|_| OAuthError::DatabaseError)?;
        Ok(())
    }

    async fn get_token(&self, access_token: &str) -> Result<Option<TokenData>, OAuthError> {
        let client = self.get_client().await?;
        let row = client
            .query_opt(
                "SELECT access_token, refresh_token, expires_at, scope, client_id FROM tokens WHERE access_token = $1",
                &[&access_token],
            )
            .await
            .map_err(|_| OAuthError::DatabaseError)?;

        Ok(row.map(|row| {
            let expires_at_system_time: SystemTime = row.get("expires_at");

            // Convert `SystemTime` back to `NaiveDateTime`
            let expires_at: NaiveDateTime = NaiveDateTime::from_timestamp(
                expires_at_system_time
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as i64,
                0,
            );

            TokenData {
                access_token: row.get("access_token"),
                refresh_token: row.get("refresh_token"),
                expires_at,
                scope: row.get("scope"),
                client_id: row.get("client_id"),
            }
        }))
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), OAuthError> {
        let client = self.get_client().await?;
        client
            .execute(
                "DELETE FROM tokens WHERE access_token = $1",
                &[&access_token],
            )
            .await
            .map_err(|_| OAuthError::DatabaseError)?;
        Ok(())
    }

    async fn get_client_by_id_async(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientData>, OAuthError> {
        let client = self.get_client().await?;
        let row = client
            .query_opt(
                "SELECT client_id, secret, redirect_uris FROM clients WHERE client_id = $1",
                &[&client_id],
            )
            .await
            .map_err(|_| OAuthError::DatabaseError)?;

        Ok(row.map(|row| ClientData {
            client_id: row.get("client_id"),
            secret: row.get("secret"),
            allowed_scopes: row
                .get::<_, String>("redirect_uris")
                .split(',')
                .map(String::from)
                .collect(),
        }))
    }
}

// Synchronous wrapper using block_on for StorageBackend compatibility
impl StorageBackend for PostgresBackend {
    fn get_client_by_id(&self, client_id: &str) -> Result<Option<ClientData>, OAuthError> {
        let rt = Runtime::new().map_err(|_| OAuthError::DatabaseError)?;
        rt.block_on(self.get_client_by_id_async(client_id))
    }
}
