# webauthn-assert CLI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a cross-platform Rust CLI that bridges CTAP2 security key assertions to WebAuthn-formatted output for use by applications like Raycast extensions authenticating to iCloud.

**Architecture:** Rust CLI using `ctap-hid-fido2` library for direct USB HID communication with security keys. Accepts JSON input via stdin (challenge, rpId, allowCredentials, origin), constructs WebAuthn `clientDataJSON`, obtains CTAP2 assertion from hardware key, and outputs WebAuthn-formatted JSON (clientDataJSON, authenticatorData, signature) to stdout. No code signing required.

**Tech Stack:** Rust 1.70+, ctap-hid-fido2, serde_json, sha2, base64

---

## Prerequisites

- Rust toolchain (rustup)
- USB security key for testing (YubiKey, SoloKey, etc.)
- macOS/Linux/Windows development environment

**Platform-specific:**
- Linux: `sudo apt install libusb-1.0-0-dev libudev-dev`
- Windows: Run as Administrator for HID access
- macOS: No special requirements

---

## JSON Contract

### Input (stdin)

```json
{
  "rpId": "apple.com",
  "challenge": "SGVsbG8gV29ybGQ",
  "origin": "https://apple.com",
  "allowCredentials": [
    {"id": "Y3JlZGVudGlhbC1pZA", "transports": ["usb"]}
  ],
  "pin": "123456",
  "timeout": 60000
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rpId` | string | Yes | Relying party identifier (domain) |
| `challenge` | string | Yes | Base64 or base64url encoded challenge from server |
| `origin` | string | Yes | Origin for clientDataJSON (e.g., "https://apple.com") |
| `allowCredentials` | array | No | List of allowed credential descriptors |
| `pin` | string | No | Security key PIN if required |
| `timeout` | number | No | Timeout in milliseconds (default: 60000) |

### Output (stdout)

**Success:**
```json
{
  "ok": true,
  "credentialId": "base64url-encoded",
  "clientDataJSON": "base64url-encoded",
  "authenticatorData": "base64url-encoded",
  "signature": "base64url-encoded",
  "userHandle": "base64url-encoded"
}
```

**Error:**
```json
{
  "ok": false,
  "error": {
    "code": "no_device",
    "message": "No security key detected. Please insert your security key."
  }
}
```

**Error codes:**
- `no_device` — No security key connected
- `no_credentials` — No matching credentials on device
- `user_canceled` — User did not touch the key within timeout
- `pin_required` — Device requires PIN but none provided
- `pin_invalid` — Provided PIN is incorrect
- `pin_blocked` — PIN blocked due to too many attempts
- `timeout` — Operation timed out
- `invalid_input` — Invalid JSON input
- `unknown` — Unexpected error

---

## Task 1: Project Setup

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `README.md`
- Create: `.gitignore`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "webauthn-assert"
version = "0.1.0"
edition = "2021"
description = "CLI tool for WebAuthn security key assertions via CTAP2"
license = "MIT"
repository = "https://github.com/user/webauthn-assert"
keywords = ["webauthn", "fido2", "ctap", "security-key", "authentication"]
categories = ["authentication", "command-line-utilities"]

[dependencies]
ctap-hid-fido2 = "3.5"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"
sha2 = "0.10"
thiserror = "1.0"

[profile.release]
lto = true
codegen-units = 1
strip = true
```

**Step 2: Create .gitignore**

```
/target
Cargo.lock
.DS_Store
*.swp
```

**Step 3: Create initial src/main.rs**

```rust
fn main() {
    println!("webauthn-assert v0.1.0");
}
```

**Step 4: Create README.md**

```markdown
# webauthn-assert

A cross-platform CLI for WebAuthn security key assertions via CTAP2.

## Requirements

- USB/NFC security key (YubiKey, SoloKey, etc.)
- Linux: `libusb-1.0-0-dev`, `libudev-dev`
- Windows: Run as Administrator

## Install

```bash
cargo install webauthn-assert
# or
brew install webauthn-assert
```

## Usage

```bash
echo '{"rpId":"example.com","challenge":"...","origin":"https://example.com"}' | webauthn-assert
```

See `webauthn-assert --help` for details.
```

**Step 5: Verify build**

Run: `cd ~/Projects/webauthn-assert && cargo build`
Expected: Build succeeds

**Step 6: Initialize git and commit**

```bash
cd ~/Projects/webauthn-assert
git init
git add .
git commit -m "chore: initialize Rust project"
```

---

## Task 2: Input/Output Models

**Files:**
- Create: `src/models.rs`
- Modify: `src/main.rs`

**Step 1: Create src/models.rs with input types**

```rust
use serde::{Deserialize, Serialize};

/// Input request from stdin
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionRequest {
    /// Relying party identifier (domain)
    pub rp_id: String,
    
    /// Base64 or base64url encoded challenge
    pub challenge: String,
    
    /// Origin for clientDataJSON (e.g., "https://apple.com")
    pub origin: String,
    
    /// Optional list of allowed credentials
    #[serde(default)]
    pub allow_credentials: Vec<CredentialDescriptor>,
    
    /// Optional PIN for the security key
    pub pin: Option<String>,
    
    /// Optional timeout in milliseconds (default: 60000)
    pub timeout: Option<u64>,
}

/// Credential descriptor
#[derive(Debug, Deserialize)]
pub struct CredentialDescriptor {
    /// Base64 or base64url encoded credential ID
    pub id: String,
    
    /// Optional transport hints
    #[serde(default)]
    pub transports: Vec<String>,
}

/// Success response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    pub ok: bool,
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

/// Error response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub ok: bool,
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

/// Error codes
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    NoDevice,
    NoCredentials,
    UserCanceled,
    PinRequired,
    PinInvalid,
    PinBlocked,
    Timeout,
    InvalidInput,
    Unknown,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoDevice => "no_device",
            Self::NoCredentials => "no_credentials",
            Self::UserCanceled => "user_canceled",
            Self::PinRequired => "pin_required",
            Self::PinInvalid => "pin_invalid",
            Self::PinBlocked => "pin_blocked",
            Self::Timeout => "timeout",
            Self::InvalidInput => "invalid_input",
            Self::Unknown => "unknown",
        }
    }
}

impl ErrorResponse {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: ErrorDetail {
                code: code.as_str().to_string(),
                message: message.into(),
            },
        }
    }
}

impl AssertionResponse {
    pub fn new(
        credential_id: String,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: Option<String>,
    ) -> Self {
        Self {
            ok: true,
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
        }
    }
}
```

**Step 2: Update src/main.rs to use models**

```rust
mod models;

use models::{AssertionRequest, ErrorCode, ErrorResponse};
use std::io::{self, Read};

fn main() {
    if let Err(e) = run() {
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Handle CLI arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--version" | "-v" => {
                println!("0.1.0");
                return Ok(());
            }
            arg => {
                output_error(ErrorCode::InvalidInput, format!("Unknown argument: {}", arg));
                std::process::exit(1);
            }
        }
    }

    // Read JSON from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    
    if input.trim().is_empty() {
        output_error(ErrorCode::InvalidInput, "No input provided. Expected JSON on stdin.");
        std::process::exit(1);
    }

    // Parse input
    let request: AssertionRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            output_error(ErrorCode::InvalidInput, format!("Invalid JSON: {}", e));
            std::process::exit(1);
        }
    };

    // TODO: Implement assertion
    eprintln!("Received request for rpId: {}", request.rp_id);
    output_error(ErrorCode::Unknown, "Not yet implemented");
    
    Ok(())
}

fn output_error(code: ErrorCode, message: impl Into<String>) {
    let response = ErrorResponse::new(code, message);
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn print_help() {
    println!(r#"webauthn-assert v0.1.0

A CLI for WebAuthn security key assertions via CTAP2.

USAGE:
    echo '<json>' | webauthn-assert
    webauthn-assert --help
    webauthn-assert --version

INPUT (JSON via stdin):
    {{
      "rpId": "example.com",
      "challenge": "<base64>",
      "origin": "https://example.com",
      "allowCredentials": [{{"id": "<base64>"}}],
      "pin": "123456",
      "timeout": 60000
    }}

OUTPUT (JSON to stdout):
    Success: {{"ok":true,"credentialId":"...","clientDataJSON":"...","authenticatorData":"...","signature":"..."}}
    Error:   {{"ok":false,"error":{{"code":"no_device","message":"..."}}}}

ERROR CODES:
    no_device      - No security key connected
    no_credentials - No matching credentials on device
    user_canceled  - User did not touch the key
    pin_required   - Device requires PIN
    pin_invalid    - Incorrect PIN
    pin_blocked    - PIN blocked
    timeout        - Operation timed out
    invalid_input  - Bad JSON input
    unknown        - Unexpected error

PLATFORM NOTES:
    Linux:   Install libusb-1.0-0-dev, libudev-dev
    Windows: Run as Administrator
    macOS:   No special requirements
"#);
}
```

**Step 3: Verify build and test**

Run: `cargo build`
Expected: Build succeeds

Run: `echo '{"rpId":"test.com","challenge":"abc","origin":"https://test.com"}' | cargo run`
Expected: Outputs JSON with "Not yet implemented" error

Run: `cargo run -- --help`
Expected: Help text displayed

**Step 4: Commit**

```bash
git add .
git commit -m "feat: add input/output models and CLI skeleton"
```

---

## Task 3: Base64 Utilities

**Files:**
- Create: `src/base64util.rs`
- Modify: `src/main.rs`

**Step 1: Create src/base64util.rs**

```rust
use base64::{engine::general_purpose, Engine};

/// Decode base64 or base64url string to bytes.
/// Handles both standard base64 and base64url (with or without padding).
pub fn decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Try base64url first (more common in WebAuthn)
    let normalized = input
        .replace('-', "+")
        .replace('_', "/");
    
    // Add padding if needed
    let padded = match normalized.len() % 4 {
        2 => format!("{}==", normalized),
        3 => format!("{}=", normalized),
        _ => normalized,
    };
    
    general_purpose::STANDARD.decode(&padded)
}

/// Encode bytes to base64url without padding (WebAuthn standard).
pub fn encode_url(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64url() {
        let input = "SGVsbG8gV29ybGQ"; // "Hello World" without padding
        let result = decode(input).unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn test_decode_base64_standard() {
        let input = "SGVsbG8gV29ybGQ="; // "Hello World" with padding
        let result = decode(input).unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn test_encode_url() {
        let result = encode_url(b"Hello World");
        assert_eq!(result, "SGVsbG8gV29ybGQ");
    }

    #[test]
    fn test_roundtrip() {
        let original = b"test data with special chars: +/=";
        let encoded = encode_url(original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
```

**Step 2: Add module to main.rs**

Add after `mod models;`:

```rust
mod base64util;
```

**Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 4: Commit**

```bash
git add .
git commit -m "feat: add base64/base64url utilities"
```

---

## Task 4: ClientDataJSON Construction

**Files:**
- Create: `src/clientdata.rs`
- Modify: `src/main.rs`

**Step 1: Create src/clientdata.rs**

```rust
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::base64util;

/// WebAuthn CollectedClientData structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectedClientData {
    /// Always "webauthn.get" for assertions
    #[serde(rename = "type")]
    typ: &'static str,
    
    /// Challenge as base64url string
    challenge: String,
    
    /// Origin (e.g., "https://apple.com")
    origin: String,
    
    /// Cross-origin flag (usually false)
    cross_origin: bool,
}

/// Build clientDataJSON and compute its SHA-256 hash.
/// 
/// Returns (clientDataJSON bytes, clientDataHash)
pub fn build_client_data(challenge: &[u8], origin: &str) -> (Vec<u8>, Vec<u8>) {
    let client_data = CollectedClientData {
        typ: "webauthn.get",
        challenge: base64util::encode_url(challenge),
        origin: origin.to_string(),
        cross_origin: false,
    };
    
    // Serialize to JSON bytes
    let json_bytes = serde_json::to_vec(&client_data)
        .expect("Failed to serialize clientDataJSON");
    
    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&json_bytes);
    let hash = hasher.finalize().to_vec();
    
    (json_bytes, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client_data() {
        let challenge = b"test-challenge";
        let origin = "https://example.com";
        
        let (json_bytes, hash) = build_client_data(challenge, origin);
        
        // Verify JSON structure
        let json_str = String::from_utf8(json_bytes.clone()).unwrap();
        assert!(json_str.contains("\"type\":\"webauthn.get\""));
        assert!(json_str.contains("\"origin\":\"https://example.com\""));
        assert!(json_str.contains("\"crossOrigin\":false"));
        
        // Verify hash is 32 bytes (SHA-256)
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_client_data_json_format() {
        let challenge = b"hello";
        let origin = "https://test.com";
        
        let (json_bytes, _) = build_client_data(challenge, origin);
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        
        assert_eq!(parsed["type"], "webauthn.get");
        assert_eq!(parsed["origin"], "https://test.com");
        assert_eq!(parsed["crossOrigin"], false);
        // Challenge should be base64url encoded
        assert!(parsed["challenge"].is_string());
    }
}
```

**Step 2: Add module to main.rs**

Add after `mod base64util;`:

```rust
mod clientdata;
```

**Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 4: Commit**

```bash
git add .
git commit -m "feat: add clientDataJSON construction"
```

---

## Task 5: CTAP Assertion Core

**Files:**
- Create: `src/ctap.rs`
- Modify: `src/main.rs`

**Step 1: Create src/ctap.rs**

```rust
use ctap_hid_fido2::{
    fidokey::GetAssertionArgsBuilder,
    Cfg, FidoKeyHid, FidoKeyHidFactory, HidParam,
};
use thiserror::Error;

use crate::models::CredentialDescriptor;
use crate::base64util;

/// Result of a successful CTAP assertion
pub struct CtapAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// Errors from CTAP operations
#[derive(Debug, Error)]
pub enum CtapError {
    #[error("No security key detected. Please insert your security key.")]
    NoDevice,
    
    #[error("No matching credentials found on the security key.")]
    NoCredentials,
    
    #[error("User did not touch the security key within the timeout period.")]
    UserCanceled,
    
    #[error("Security key requires a PIN. Please provide one.")]
    PinRequired,
    
    #[error("Invalid PIN provided.")]
    PinInvalid,
    
    #[error("PIN is blocked due to too many incorrect attempts.")]
    PinBlocked,
    
    #[error("Operation timed out.")]
    Timeout,
    
    #[error("CTAP error: {0}")]
    Other(String),
}

/// Perform a CTAP2 GetAssertion operation.
pub fn get_assertion(
    rp_id: &str,
    client_data_hash: &[u8],
    allow_credentials: &[CredentialDescriptor],
    pin: Option<&str>,
) -> Result<CtapAssertion, CtapError> {
    // Configure the library
    let cfg = Cfg::init();
    
    // Find a connected FIDO device
    let device = match FidoKeyHidFactory::create(&cfg) {
        Ok(d) => d,
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("no device") || msg.contains("not found") {
                return Err(CtapError::NoDevice);
            }
            return Err(CtapError::Other(e.to_string()));
        }
    };
    
    // Build the assertion request
    let mut builder = GetAssertionArgsBuilder::new(rp_id, client_data_hash);
    
    // Add allowed credentials
    for cred in allow_credentials {
        if let Ok(cred_id) = base64util::decode(&cred.id) {
            builder = builder.add_credential_id(&cred_id);
        }
    }
    
    // Add PIN if provided
    if let Some(p) = pin {
        builder = builder.pin(p);
    }
    
    let args = builder.build();
    
    // Perform the assertion
    // Note: This will prompt "Touch the sensor on the authenticator"
    let assertions = match device.get_assertion_with_args(&args) {
        Ok(a) => a,
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            
            if msg.contains("no credentials") || msg.contains("credential") {
                return Err(CtapError::NoCredentials);
            }
            if msg.contains("pin required") || msg.contains("pin needed") {
                return Err(CtapError::PinRequired);
            }
            if msg.contains("pin invalid") || msg.contains("wrong pin") {
                return Err(CtapError::PinInvalid);
            }
            if msg.contains("pin blocked") {
                return Err(CtapError::PinBlocked);
            }
            if msg.contains("timeout") || msg.contains("timed out") {
                return Err(CtapError::Timeout);
            }
            if msg.contains("cancel") || msg.contains("user") {
                return Err(CtapError::UserCanceled);
            }
            
            return Err(CtapError::Other(e.to_string()));
        }
    };
    
    // Get the first assertion (there should be at least one)
    let assertion = assertions.into_iter().next()
        .ok_or_else(|| CtapError::NoCredentials)?;
    
    Ok(CtapAssertion {
        credential_id: assertion.credential_id,
        authenticator_data: assertion.auth_data,
        signature: assertion.signature,
        user_handle: if assertion.user.id.is_empty() {
            None
        } else {
            Some(assertion.user.id)
        },
    })
}

/// Check if any FIDO device is connected
pub fn is_device_connected() -> bool {
    let cfg = Cfg::init();
    FidoKeyHidFactory::create(&cfg).is_ok()
}
```

**Step 2: Add module to main.rs**

Add after `mod clientdata;`:

```rust
mod ctap;
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Build succeeds (may show warnings about unused code)

**Step 4: Commit**

```bash
git add .
git commit -m "feat: add CTAP assertion core"
```

---

## Task 6: Main Integration

**Files:**
- Modify: `src/main.rs`

**Step 1: Replace the run() function with full implementation**

```rust
mod models;
mod base64util;
mod clientdata;
mod ctap;

use models::{AssertionRequest, AssertionResponse, ErrorCode, ErrorResponse};
use std::io::{self, Read};

fn main() {
    if let Err(e) = run() {
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Handle CLI arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--version" | "-v" => {
                println!("0.1.0");
                return Ok(());
            }
            "--check" => {
                // Quick check if a device is connected
                if ctap::is_device_connected() {
                    println!("Security key detected");
                    return Ok(());
                } else {
                    eprintln!("No security key detected");
                    std::process::exit(1);
                }
            }
            arg => {
                output_error(ErrorCode::InvalidInput, format!("Unknown argument: {}", arg));
                std::process::exit(1);
            }
        }
    }

    // Read JSON from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    
    if input.trim().is_empty() {
        output_error(ErrorCode::InvalidInput, "No input provided. Expected JSON on stdin.");
        std::process::exit(1);
    }

    // Parse input
    let request: AssertionRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            output_error(ErrorCode::InvalidInput, format!("Invalid JSON: {}", e));
            std::process::exit(1);
        }
    };

    // Decode challenge
    let challenge = match base64util::decode(&request.challenge) {
        Ok(c) => c,
        Err(e) => {
            output_error(ErrorCode::InvalidInput, format!("Invalid challenge encoding: {}", e));
            std::process::exit(1);
        }
    };

    // Build clientDataJSON and hash
    let (client_data_json, client_data_hash) = clientdata::build_client_data(&challenge, &request.origin);

    // Perform CTAP assertion
    let assertion = match ctap::get_assertion(
        &request.rp_id,
        &client_data_hash,
        &request.allow_credentials,
        request.pin.as_deref(),
    ) {
        Ok(a) => a,
        Err(e) => {
            let code = match &e {
                ctap::CtapError::NoDevice => ErrorCode::NoDevice,
                ctap::CtapError::NoCredentials => ErrorCode::NoCredentials,
                ctap::CtapError::UserCanceled => ErrorCode::UserCanceled,
                ctap::CtapError::PinRequired => ErrorCode::PinRequired,
                ctap::CtapError::PinInvalid => ErrorCode::PinInvalid,
                ctap::CtapError::PinBlocked => ErrorCode::PinBlocked,
                ctap::CtapError::Timeout => ErrorCode::Timeout,
                ctap::CtapError::Other(_) => ErrorCode::Unknown,
            };
            output_error(code, e.to_string());
            std::process::exit(1);
        }
    };

    // Build response
    let response = AssertionResponse::new(
        base64util::encode_url(&assertion.credential_id),
        base64util::encode_url(&client_data_json),
        base64util::encode_url(&assertion.authenticator_data),
        base64util::encode_url(&assertion.signature),
        assertion.user_handle.map(|h| base64util::encode_url(&h)),
    );

    // Output success
    println!("{}", serde_json::to_string(&response)?);
    
    Ok(())
}

fn output_error(code: ErrorCode, message: impl Into<String>) {
    let response = ErrorResponse::new(code, message);
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn print_help() {
    println!(r#"webauthn-assert v0.1.0

A CLI for WebAuthn security key assertions via CTAP2.

USAGE:
    echo '<json>' | webauthn-assert
    webauthn-assert --help
    webauthn-assert --version
    webauthn-assert --check

COMMANDS:
    --help, -h     Show this help message
    --version, -v  Show version
    --check        Check if a security key is connected

INPUT (JSON via stdin):
    {{
      "rpId": "example.com",
      "challenge": "<base64>",
      "origin": "https://example.com",
      "allowCredentials": [{{"id": "<base64>"}}],
      "pin": "123456",
      "timeout": 60000
    }}

OUTPUT (JSON to stdout):
    Success: {{"ok":true,"credentialId":"...","clientDataJSON":"...","authenticatorData":"...","signature":"..."}}
    Error:   {{"ok":false,"error":{{"code":"no_device","message":"..."}}}}

ERROR CODES:
    no_device      - No security key connected
    no_credentials - No matching credentials on device
    user_canceled  - User did not touch the key
    pin_required   - Device requires PIN
    pin_invalid    - Incorrect PIN
    pin_blocked    - PIN blocked
    timeout        - Operation timed out
    invalid_input  - Bad JSON input
    unknown        - Unexpected error

PLATFORM NOTES:
    Linux:   Install libusb-1.0-0-dev, libudev-dev
    Windows: Run as Administrator
    macOS:   No special requirements

EXAMPLE (iCloud authentication):
    echo '{{
      "rpId": "apple.com",
      "challenge": "'$CHALLENGE'",
      "origin": "https://apple.com",
      "allowCredentials": [{{"id": "'$KEY_HANDLE'"}}]
    }}' | webauthn-assert
"#);
}
```

**Step 2: Verify build**

Run: `cargo build --release`
Expected: Build succeeds

**Step 3: Test with --help and --check**

Run: `cargo run -- --help`
Expected: Help text displayed

Run: `cargo run -- --check`
Expected: Either "Security key detected" or "No security key detected" depending on hardware

**Step 4: Commit**

```bash
git add .
git commit -m "feat: integrate CTAP with main entry point"
```

---

## Task 7: Input Validation

**Files:**
- Create: `src/validate.rs`
- Modify: `src/main.rs`

**Step 1: Create src/validate.rs**

```rust
use crate::models::AssertionRequest;

/// Maximum allowed challenge size (prevent memory abuse)
const MAX_CHALLENGE_SIZE: usize = 1024;

/// Maximum allowed credential ID size
const MAX_CREDENTIAL_ID_SIZE: usize = 1024;

/// Maximum number of allowed credentials
const MAX_CREDENTIALS: usize = 100;

#[derive(Debug)]
pub struct ValidationError(pub String);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validate the assertion request
pub fn validate_request(request: &AssertionRequest) -> Result<(), ValidationError> {
    // Validate rpId
    if request.rp_id.is_empty() {
        return Err(ValidationError("rpId cannot be empty".into()));
    }
    if request.rp_id.contains('/') || request.rp_id.contains(':') {
        return Err(ValidationError("rpId must be a domain, not a URL".into()));
    }
    if request.rp_id.len() > 253 {
        return Err(ValidationError("rpId too long (max 253 chars)".into()));
    }
    
    // Validate challenge
    if request.challenge.is_empty() {
        return Err(ValidationError("challenge cannot be empty".into()));
    }
    if request.challenge.len() > MAX_CHALLENGE_SIZE {
        return Err(ValidationError(format!(
            "challenge too large (max {} bytes encoded)", MAX_CHALLENGE_SIZE
        )));
    }
    
    // Validate origin
    if request.origin.is_empty() {
        return Err(ValidationError("origin cannot be empty".into()));
    }
    if !request.origin.starts_with("https://") && !request.origin.starts_with("http://") {
        return Err(ValidationError("origin must start with https:// or http://".into()));
    }
    
    // Validate allowCredentials
    if request.allow_credentials.len() > MAX_CREDENTIALS {
        return Err(ValidationError(format!(
            "too many allowCredentials (max {})", MAX_CREDENTIALS
        )));
    }
    for (i, cred) in request.allow_credentials.iter().enumerate() {
        if cred.id.is_empty() {
            return Err(ValidationError(format!(
                "allowCredentials[{}].id cannot be empty", i
            )));
        }
        if cred.id.len() > MAX_CREDENTIAL_ID_SIZE {
            return Err(ValidationError(format!(
                "allowCredentials[{}].id too large", i
            )));
        }
    }
    
    // Validate timeout
    if let Some(timeout) = request.timeout {
        if timeout == 0 {
            return Err(ValidationError("timeout cannot be 0".into()));
        }
        if timeout > 300000 {
            return Err(ValidationError("timeout too large (max 5 minutes)".into()));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CredentialDescriptor;

    fn make_request() -> AssertionRequest {
        AssertionRequest {
            rp_id: "example.com".into(),
            challenge: "dGVzdA".into(),
            origin: "https://example.com".into(),
            allow_credentials: vec![],
            pin: None,
            timeout: None,
        }
    }

    #[test]
    fn test_valid_request() {
        let req = make_request();
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn test_empty_rp_id() {
        let mut req = make_request();
        req.rp_id = "".into();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn test_rp_id_is_url() {
        let mut req = make_request();
        req.rp_id = "https://example.com".into();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn test_empty_origin() {
        let mut req = make_request();
        req.origin = "".into();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn test_invalid_origin_scheme() {
        let mut req = make_request();
        req.origin = "ftp://example.com".into();
        assert!(validate_request(&req).is_err());
    }
}
```

**Step 2: Add module and integrate in main.rs**

Add after `mod ctap;`:

```rust
mod validate;
```

Add validation after parsing, before decoding challenge:

```rust
    // Validate input
    if let Err(e) = validate::validate_request(&request) {
        output_error(ErrorCode::InvalidInput, e.to_string());
        std::process::exit(1);
    }
```

**Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 4: Commit**

```bash
git add .
git commit -m "feat: add input validation"
```

---

## Task 8: Integration Tests

**Files:**
- Create: `tests/integration.rs`

**Step 1: Create tests/integration.rs**

```rust
use std::process::{Command, Stdio};
use std::io::Write;

fn run_cli(input: &str) -> (String, i32) {
    let mut child = Command::new("cargo")
        .args(["run", "--quiet", "--"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn process");
    
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).expect("Failed to write stdin");
    }
    
    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let code = output.status.code().unwrap_or(-1);
    
    (stdout, code)
}

#[test]
fn test_help_flag() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "--help"])
        .output()
        .expect("Failed to run");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("webauthn-assert"));
    assert!(stdout.contains("USAGE"));
    assert!(output.status.success());
}

#[test]
fn test_version_flag() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "--version"])
        .output()
        .expect("Failed to run");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim() == "0.1.0");
    assert!(output.status.success());
}

#[test]
fn test_empty_input() {
    let (stdout, code) = run_cli("");
    
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["error"]["code"], "invalid_input");
    assert_ne!(code, 0);
}

#[test]
fn test_invalid_json() {
    let (stdout, code) = run_cli("not valid json");
    
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["error"]["code"], "invalid_input");
    assert_ne!(code, 0);
}

#[test]
fn test_missing_required_fields() {
    let (stdout, code) = run_cli(r#"{"rpId": "test.com"}"#);
    
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["error"]["code"], "invalid_input");
    assert_ne!(code, 0);
}

#[test]
fn test_invalid_rp_id() {
    let input = r#"{
        "rpId": "https://example.com",
        "challenge": "dGVzdA",
        "origin": "https://example.com"
    }"#;
    
    let (stdout, code) = run_cli(input);
    
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["error"]["code"], "invalid_input");
    assert!(parsed["error"]["message"].as_str().unwrap().contains("domain"));
    assert_ne!(code, 0);
}

#[test]
fn test_invalid_origin() {
    let input = r#"{
        "rpId": "example.com",
        "challenge": "dGVzdA",
        "origin": "ftp://example.com"
    }"#;
    
    let (stdout, code) = run_cli(input);
    
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["error"]["code"], "invalid_input");
    assert_ne!(code, 0);
}

// Note: Tests that require actual hardware are skipped in CI
// Run with a security key connected for full testing:
// WEBAUTHN_TEST_HARDWARE=1 cargo test -- --ignored

#[test]
#[ignore]
fn test_no_device_error() {
    // This test assumes no device is connected
    let input = r#"{
        "rpId": "example.com",
        "challenge": "dGVzdA",
        "origin": "https://example.com"
    }"#;
    
    let (stdout, code) = run_cli(input);
    
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(parsed["ok"], false);
    // Could be no_device or no_credentials depending on setup
    assert_ne!(code, 0);
}
```

**Step 2: Run tests**

Run: `cargo test`
Expected: All non-ignored tests pass

**Step 3: Commit**

```bash
git add .
git commit -m "test: add integration tests"
```

---

## Task 9: Homebrew Formula

**Files:**
- Create: `Formula/webauthn-assert.rb`
- Modify: `README.md`

**Step 1: Create Formula/webauthn-assert.rb**

```ruby
class WebauthnAssert < Formula
  desc "CLI for WebAuthn security key assertions via CTAP2"
  homepage "https://github.com/user/webauthn-assert"
  url "https://github.com/user/webauthn-assert/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"

  depends_on "rust" => :build

  on_linux do
    depends_on "pkg-config" => :build
    depends_on "libusb"
    depends_on "systemd" # for libudev
  end

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "webauthn-assert", shell_output("#{bin}/webauthn-assert --help")
    assert_match "0.1.0", shell_output("#{bin}/webauthn-assert --version")
  end
end
```

**Step 2: Create LICENSE file**

```
MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Step 3: Update README.md with complete documentation**

```markdown
# webauthn-assert

A cross-platform CLI for WebAuthn security key assertions via CTAP2.

This tool enables applications to authenticate using hardware security keys (YubiKey, SoloKey, etc.) by bridging CTAP2 protocol to WebAuthn-formatted responses.

## Requirements

- USB/NFC security key (YubiKey 5, SoloKey, Nitrokey, etc.)
- **Linux:** `libusb-1.0-0-dev`, `libudev-dev`
- **Windows:** Run as Administrator
- **macOS:** No special requirements

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap user/webauthn-assert
brew install webauthn-assert
```

### Cargo (all platforms)

```bash
cargo install webauthn-assert
```

### From source

```bash
git clone https://github.com/user/webauthn-assert.git
cd webauthn-assert
cargo build --release
cp target/release/webauthn-assert /usr/local/bin/
```

## Usage

```bash
# Check if security key is connected
webauthn-assert --check

# Perform assertion
echo '{
  "rpId": "example.com",
  "challenge": "SGVsbG8gV29ybGQ",
  "origin": "https://example.com",
  "allowCredentials": [{"id": "Y3JlZGVudGlhbC1pZA"}]
}' | webauthn-assert
```

## Input Format (JSON via stdin)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rpId` | string | Yes | Relying party identifier (domain only, not URL) |
| `challenge` | string | Yes | Base64 or base64url encoded challenge |
| `origin` | string | Yes | Origin for clientDataJSON (e.g., `https://example.com`) |
| `allowCredentials` | array | No | List of allowed credential descriptors |
| `pin` | string | No | Security key PIN if required |
| `timeout` | number | No | Timeout in milliseconds (default: 60000) |

### Credential Descriptor

```json
{"id": "base64-credential-id", "transports": ["usb", "nfc"]}
```

## Output Format (JSON to stdout)

### Success

```json
{
  "ok": true,
  "credentialId": "base64url-encoded",
  "clientDataJSON": "base64url-encoded",
  "authenticatorData": "base64url-encoded",
  "signature": "base64url-encoded",
  "userHandle": "base64url-encoded"
}
```

### Error

```json
{
  "ok": false,
  "error": {
    "code": "no_device",
    "message": "No security key detected. Please insert your security key."
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `no_device` | No security key connected |
| `no_credentials` | No matching credentials on device |
| `user_canceled` | User did not touch the key within timeout |
| `pin_required` | Device requires PIN but none provided |
| `pin_invalid` | Provided PIN is incorrect |
| `pin_blocked` | PIN blocked due to too many attempts |
| `timeout` | Operation timed out |
| `invalid_input` | Invalid JSON input |
| `unknown` | Unexpected error |

## Example: iCloud Authentication

```bash
#!/bin/bash
# Example: Using with iCloud security key authentication

# 1. Get challenge from Apple (via your app's SRP flow)
CHALLENGE="..."
KEY_HANDLE="..."

# 2. Call webauthn-assert
RESPONSE=$(echo "{
  \"rpId\": \"apple.com\",
  \"challenge\": \"$CHALLENGE\",
  \"origin\": \"https://apple.com\",
  \"allowCredentials\": [{\"id\": \"$KEY_HANDLE\"}]
}" | webauthn-assert)

# 3. Check result
if echo "$RESPONSE" | jq -e '.ok' > /dev/null; then
  # Extract fields for Apple's /verify/security/key endpoint
  CLIENT_DATA=$(echo "$RESPONSE" | jq -r '.clientDataJSON')
  AUTH_DATA=$(echo "$RESPONSE" | jq -r '.authenticatorData')
  SIGNATURE=$(echo "$RESPONSE" | jq -r '.signature')
  CREDENTIAL_ID=$(echo "$RESPONSE" | jq -r '.credentialId')
  
  # Send to Apple...
else
  ERROR=$(echo "$RESPONSE" | jq -r '.error.message')
  echo "Authentication failed: $ERROR" >&2
  exit 1
fi
```

## Platform Notes

### Linux

Install dependencies:
```bash
sudo apt install libusb-1.0-0-dev libudev-dev
```

Add udev rules for non-root access:
```bash
# /etc/udev/rules.d/70-u2f.rules
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"
```

### Windows

Must run with Administrator privileges for USB HID access.

### macOS

No special configuration required.

## License

MIT
```

**Step 4: Commit**

```bash
git add .
git commit -m "docs: add Homebrew formula and comprehensive README"
```

---

## Task 10: CI/CD Setup

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`

**Step 1: Create .github/workflows/ci.yml**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Linux dependencies
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libusb-1.0-0-dev libudev-dev
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
      
      - name: Check formatting
        run: cargo fmt --check
      
      - name: Clippy
        run: cargo clippy -- -D warnings
      
      - name: Build
        run: cargo build --verbose
      
      - name: Run tests
        run: cargo test --verbose

  build-release:
    needs: test
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            artifact: webauthn-assert-linux-x86_64
          - os: macos-latest
            target: x86_64-apple-darwin
            artifact: webauthn-assert-macos-x86_64
          - os: macos-latest
            target: aarch64-apple-darwin
            artifact: webauthn-assert-macos-aarch64
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: webauthn-assert-windows-x86_64.exe
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Linux dependencies
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libusb-1.0-0-dev libudev-dev
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
        with:
          targets: ${{ matrix.target }}
      
      - name: Build release
        run: cargo build --release --target ${{ matrix.target }}
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.artifact }}
          path: target/${{ matrix.target }}/release/webauthn-assert${{ runner.os == 'Windows' && '.exe' || '' }}
```

**Step 2: Create .github/workflows/release.yml**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            artifact: webauthn-assert-linux-x86_64
          - os: macos-latest
            target: x86_64-apple-darwin
            artifact: webauthn-assert-macos-x86_64
          - os: macos-latest
            target: aarch64-apple-darwin
            artifact: webauthn-assert-macos-aarch64
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: webauthn-assert-windows-x86_64.exe
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Linux dependencies
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libusb-1.0-0-dev libudev-dev
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
        with:
          targets: ${{ matrix.target }}
      
      - name: Build release
        run: cargo build --release --target ${{ matrix.target }}
      
      - name: Package (Unix)
        if: runner.os != 'Windows'
        run: |
          cd target/${{ matrix.target }}/release
          tar czvf ../../../${{ matrix.artifact }}.tar.gz webauthn-assert
      
      - name: Package (Windows)
        if: runner.os == 'Windows'
        run: |
          cd target/${{ matrix.target }}/release
          7z a ../../../${{ matrix.artifact }}.zip webauthn-assert.exe
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.artifact }}
          path: ${{ matrix.artifact }}.${{ runner.os == 'Windows' && 'zip' || 'tar.gz' }}

  release:
    needs: build
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: artifacts
      
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: artifacts/**/*
          generate_release_notes: true
```

**Step 3: Commit**

```bash
mkdir -p .github/workflows
git add .
git commit -m "ci: add GitHub Actions workflows"
```

---

## Final Verification

**Step 1: Full build and test**

```bash
cargo fmt
cargo clippy
cargo build --release
cargo test
```

**Step 2: Manual test with security key (if available)**

```bash
# Check device
./target/release/webauthn-assert --check

# Test assertion (will fail with no_credentials unless you have a registered credential)
echo '{"rpId":"example.com","challenge":"dGVzdA","origin":"https://example.com"}' | ./target/release/webauthn-assert
```

**Step 3: Create initial tag**

```bash
git tag v0.1.0
```

---

## Summary

The implementation creates a minimal, focused CLI tool that:

1. **Cross-platform** — Rust compiles to macOS, Windows, Linux
2. **No code signing** — Direct USB HID access, Homebrew builds from source
3. **JSON I/O** — Easy integration from any language (Node.js, Python, etc.)
4. **WebAuthn output** — Produces clientDataJSON, authenticatorData, signature
5. **Robust error handling** — Typed error codes for programmatic handling
6. **Well-tested** — Unit and integration tests
7. **Easy distribution** — Homebrew formula, cargo install, GitHub releases
