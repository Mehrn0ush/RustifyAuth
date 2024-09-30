# RustifyAuth

**RustifyAuth** is an OAuth 2.0 and OAuth 2.1 compliant authorization server library written in Rust. It provides developers with a robust and flexible solution for implementing secure, standards-compliant authorization mechanisms.

## 🚀 Features

- **OAuth 2.0 & 2.1 Compliance**: Implements key authorization flows such as Authorization Code with PKCE, Client Credentials, and others.
- **Enhanced Security**: Includes advanced security features like MFA (Multi-Factor Authentication), rate-limiting, token encryption (JWE), and more.
- **Token Management**: Built-in support for token introspection, revocation, and secure JWT handling with RSA/ECC and quantum-resistant algorithms (Dilithium/Falcon).
- **Pluggable Storage**: Flexible backend support (In-Memory, Redis, SQL) for storing client data and tokens.

## 📦 Getting Started

### Prerequisites

Before getting started, ensure you have the following installed on your system:

- Rust (Stable toolchain)
- Cargo (Rust package manager)

### Installation

To install and build **RustifyAuth** locally, clone the repository and use Cargo:

```bash
git clone https://github.com/Mehrn0ush/RustifyAuth.git
cd RustifyAuth
cargo build
```

### Running the Server
Once you've built the project, you can start the server by running:

```bash
cargo run
```

### 🔧 Running Tests

RustifyAuth comes with a comprehensive suite of unit and integration tests. To execute the tests, use:

```bash
cargo test
```

### Notes
For testing purposes, the repository includes client_cert.pem, client_key.pem, custom_cert.pem, and custom_key.pem. These files are used for the Dynamic Client Registration as per RFC 7591 and are provided for local development and testing only.

Note: The keys and certificates in this repository are not intended for production use. Please generate your own keys and certificates if you intend to use this in a live environment.

Public and Private Key Files
client_cert.pem: The client certificate used during the registration process.
client_key.pem: The private key corresponding to the client certificate.
custom_cert.pem: A custom certificate used for encrypting data.
custom_key.pem: The private key corresponding to the custom certificate.
These keys and certificates are self-signed and intended solely for testing.

The custom_cert.srl file is a serial number file used by OpenSSL when generating certificates. It keeps track of the serial numbers of the certificates that have been signed by the Certificate Authority (CA).



How to Generate Your Own Keys and Certificates
You can generate your own public and private keys using OpenSSL. Here is a step-by-step guide on how to do this:

### Generate a Private Key
Run the following command to generate a 2048-bit private key:
```bash
openssl genrsa -out client_key.pem 2048
```
### Generate a Certificate Signing Request (CSR)
Use the private key to generate a certificate signing request:

```bash
openssl req -new -key client_key.pem -out client.csr
```
### Generate a Self-Signed Certificate
Create a self-signed certificate from the CSR, valid for 365 days:

```bash
openssl x509 -req -days 365 -in client.csr -signkey client_key.pem -out client_cert.pem
```
### Generate a Custom Private Key and Certificate
You can also generate a custom private key and certificate for additional use:
```bash
openssl genrsa -out custom_key.pem 2048
openssl req -new -key custom_key.pem -out custom.csr
openssl x509 -req -days 365 -in custom.csr -signkey custom_key.pem -out custom_cert.pem
```

### Using the Keys for Testing
These keys are used in the Dynamic Client Registration process for securing communications and authenticating clients. In your local testing environment, you can simply point to these keys in the relevant configuration files or environment variables.

### Example:

client_key.pem and client_cert.pem will be used during client registration.
custom_key.pem and custom_cert.pem can be used for other secure communication scenarios.
Feel free to generate your own certificates if you prefer not to use the provided ones for testing.

Security Notice
Do not use the provided certificates and private keys in production environments. Always generate your own secure keys for production deployments to ensure the safety of your application and users.

## 🎉 Hacktoberfest 2024

We are excited to be part of **Hacktoberfest 2024**! Whether you're interested in fixing bugs, improving documentation, writing tests, or adding new features, we welcome your contributions. Check out the [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

### How to Contribute

- **Find Issues**: Look for issues tagged with `hacktoberfest` for contribution opportunities.
- **Fork the Repository**: Click the fork button at the top right of this page to create your own copy.
- **Create a Feature Branch**: Use a descriptive name for your branch (e.g., `fix-auth-bug`).
- **Submit a Pull Request**: Once your changes are ready, submit a pull request. Ensure your contributions align with the [`CONTRIBUTING.md`](CONTRIBUTING.md) guidelines.

### 🤝 Contributing

We welcome contributions of all kinds, including:

- 🐛 **Bug Fixes**
- ✨ **Feature Implementations**
- 🚀 **Code Optimizations**
- 📚 **Documentation Improvements**

For detailed instructions, see the [`CONTRIBUTING.md`](CONTRIBUTING.md).

## 📞 Contact

For any questions or assistance, feel free to reach out:

- **Email**: [Mehrnoush.vaseghi@gmail.com](mailto:Mehrnoush.vaseghi@gmail.com)
- **GitHub Issues**: [Open an issue](https://github.com/Mehrn0ush/RustifyAuth/issues) for questions, feature requests, or feedback.

Thank you for checking out **RustifyAuth**! We look forward to your contributions and feedback.