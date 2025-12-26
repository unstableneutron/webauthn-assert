# webauthn-assert

Cross-platform CLI for WebAuthn security key assertions via CTAP2.

## Commands
- `cargo build` / `cargo build --release` - Build
- `cargo test` - Run all tests
- `cargo test test_name` - Run single test
- `cargo fmt` - Format code
- `cargo clippy -- -D warnings` - Lint (must pass with no warnings)

## Architecture
Single binary CLI that reads JSON from stdin, performs CTAP2 assertion, outputs JSON to stdout.
- `main.rs` - CLI entry, argument parsing, I/O
- `ctap.rs` - CTAP2/FIDO2 device communication via ctap-hid-fido2
- `webauthn.rs` - ClientDataJSON construction
- `base64util.rs` - Base64/base64url encoding/decoding utilities
- `models.rs` - Request/response JSON models
- `error.rs` - Error types and codes

## Code Style
- Use `thiserror` for error types, `anyhow` for propagation
- Base64url without padding for WebAuthn challenge encoding (`URL_SAFE_NO_PAD`)
- Standard base64 for output fields (credentialID, clientData, etc.)
- Keep modules focused; no comments unless complex logic requires context
