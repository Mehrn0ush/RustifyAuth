-- Clients Table
CREATE TABLE clients (
    client_id VARCHAR PRIMARY KEY,
    client_secret VARCHAR NOT NULL,
    redirect_uris JSONB NOT NULL,
    grant_types JSONB,
    response_types JSONB,
    software_statement TEXT
);

-- Tokens Table
CREATE TABLE tokens (
    access_token VARCHAR PRIMARY KEY,
    refresh_token VARCHAR,
    expires_at TIMESTAMP,
    scope VARCHAR,
    client_id VARCHAR REFERENCES clients(client_id),
    token_type VARCHAR DEFAULT 'Bearer'
);

-- Indexes for performance
CREATE INDEX idx_access_token ON tokens(access_token);
CREATE INDEX idx_client_id ON clients(client_id);

