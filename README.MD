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

### Running the Server
Once you've built the project, you can start the server by running:

```bash
cargo run


### 🔧 Running Tests

RustifyAuth comes with a comprehensive suite of unit and integration tests. To execute the tests, use:

```bash
cargo test




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