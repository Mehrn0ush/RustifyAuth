use dotenv::dotenv;
use pem::Pem;
use rustls::version::{TLS12, TLS13};
use rustls::{
    Certificate, ClientConfig, PrivateKey, RootCertStore, SupportedCipherSuite, SupportedKxGroup,
};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

static CIPHER_SUITES: &[SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

fn select_cipher_suites() -> &'static [SupportedCipherSuite] {
    CIPHER_SUITES
}

static KX_GROUPS: &[&SupportedKxGroup] = &[
    &rustls::kx_group::X25519,
    &rustls::kx_group::SECP256R1,
    &rustls::kx_group::SECP384R1,
];

fn select_kx_groups() -> &'static [&'static SupportedKxGroup] {
    KX_GROUPS
}

/// Configures TLS with proper security settings.
pub fn configure_tls() -> ClientConfig {
    dotenv().ok();

    // Load root certificates
    let root_cert_store = load_root_certificates();

    // Select cipher suites and key exchange groups
    let cipher_suites = select_cipher_suites();
    let kx_groups = select_kx_groups();

    // Build the ClientConfig using the builder pattern
    let config = if let Some((certs, key)) = load_client_certificates() {
        ClientConfig::builder()
            .with_cipher_suites(cipher_suites)
            .with_kx_groups(kx_groups)
            .with_protocol_versions(&[&TLS13, &TLS12])
            .expect("Failed to create client config")
            .with_root_certificates(root_cert_store)
            .with_single_cert(certs, key)
            .expect("Failed to set client cert")
    } else {
        ClientConfig::builder()
            .with_cipher_suites(cipher_suites)
            .with_kx_groups(kx_groups)
            .with_protocol_versions(&[&TLS13, &TLS12])
            .expect("Failed to create client config")
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    };

    config
}

/// Loads the root certificates, including system and optionally custom certificates.
fn load_root_certificates() -> RootCertStore {
    let mut root_store = RootCertStore::empty();

    // Load system root certificates
    root_store.add_server_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref().to_vec(),
            ta.subject_public_key_info.as_ref().to_vec(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref().to_vec()),
        )
    }));

    // Optionally load custom certificates
    if let Ok(custom_certs_path) = env::var("CUSTOM_CERTS_PATH") {
        if let Ok(custom_certs) = load_custom_certificates(&custom_certs_path) {
            for cert in custom_certs {
                root_store
                    .add(&cert)
                    .expect("Failed to add custom certificate");
            }
        }
    }

    root_store
}

/// Loads custom certificates from a PEM file.
fn load_custom_certificates(path: &str) -> Result<Vec<Certificate>, std::io::Error> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);

    let mut certs = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        let cert_der = item?; // Handle potential errors
        let cert_bytes = cert_der.as_ref().to_vec(); // Get Vec<u8>
        certs.push(Certificate(cert_bytes));
    }

    Ok(certs)
}

/// Loads the client certificates and private key for mutual TLS (optional).
fn load_client_certificates() -> Option<(Vec<Certificate>, PrivateKey)> {
    // Load client certs (example path)
    if let Ok(client_cert_path) = env::var("CLIENT_CERT_PATH") {
        if let Ok(certs) = load_custom_certificates(&client_cert_path) {
            if let Ok(client_key_path) = env::var("CLIENT_KEY_PATH") {
                if let Ok(key) = load_private_key(&client_key_path) {
                    return Some((certs, key));
                }
            }
        }
    }
    None
}

/// Loads a private key from a PEM file.

fn load_private_key(path: &str) -> Result<PrivateKey, std::io::Error> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    let mut key_data = String::new();
    reader.read_to_string(&mut key_data)?;

    let pem = pem::parse(key_data).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("PEM parse error: {}", e),
        )
    })?;

    // Ensure it's a private key
    if pem.tag() != "PRIVATE KEY" && pem.tag() != "RSA PRIVATE KEY" && pem.tag() != "EC PRIVATE KEY"
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No valid private key found",
        ));
    }

    Ok(PrivateKey(pem.contents().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_tls_setup() {
        let config = configure_tls();

        // Attempt to create a ClientConnection to test the config
        let server_name = "example.com".try_into().unwrap();
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name);

        assert!(
            conn.is_ok(),
            "Failed to create ClientConnection with the given config"
        );
    }
}
