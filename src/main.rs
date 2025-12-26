mod base64util;
mod ctap;
mod error;
mod models;
mod webauthn;

use models::{AssertionRequest, AssertionResponse, ErrorCode, ErrorResponse};
use std::io::{self, Read};

fn main() {
    if let Err(e) = run() {
        output_error(ErrorCode::Unknown, e.to_string());
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut apple_mode = false;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--version" | "-v" => {
                println!("0.1.0");
                return Ok(());
            }
            "--check" => {
                match ctap::enumerate_devices() {
                    Ok(device) => {
                        println!("{}", serde_json::json!({"ok": true, "device": device}));
                    }
                    Err(e) => {
                        output_error(e.code(), e.to_string());
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
            "--apple" => {
                apple_mode = true;
            }
            arg => {
                output_error(
                    ErrorCode::InvalidInput,
                    format!("Unknown argument: {}", arg),
                );
                std::process::exit(1);
            }
        }
    }

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    if input.trim().is_empty() {
        output_error(
            ErrorCode::InvalidInput,
            "No input provided. Expected JSON on stdin.",
        );
        std::process::exit(1);
    }

    let request: AssertionRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            output_error(ErrorCode::InvalidInput, format!("Invalid JSON: {}", e));
            std::process::exit(1);
        }
    };

    if request.rp_id.is_empty() {
        output_error(ErrorCode::InvalidInput, "rpId is required");
        std::process::exit(1);
    }
    if request.challenge.is_empty() {
        output_error(ErrorCode::InvalidInput, "challenge is required");
        std::process::exit(1);
    }
    if request.origin.is_empty() {
        output_error(ErrorCode::InvalidInput, "origin is required");
        std::process::exit(1);
    }

    if apple_mode {
        if request.rp_id != "apple.com" {
            output_error(
                ErrorCode::InvalidInput,
                "Apple mode requires rpId to be exactly 'apple.com'",
            );
            std::process::exit(1);
        }
        if request.origin != "https://apple.com" {
            output_error(
                ErrorCode::InvalidInput,
                "Apple mode requires origin to be exactly 'https://apple.com'",
            );
            std::process::exit(1);
        }
    }

    let challenge_bytes = match base64util::decode(&request.challenge) {
        Ok(b) => b,
        Err(e) => {
            output_error(
                ErrorCode::InvalidInput,
                format!("Invalid challenge encoding: {}", e),
            );
            std::process::exit(1);
        }
    };

    let client_data_json = webauthn::build_client_data_json(&challenge_bytes, &request.origin);

    let mut allow_credentials: Vec<Vec<u8>> = Vec::with_capacity(request.allow_credentials.len());
    for cred in &request.allow_credentials {
        match base64util::decode(&cred.id) {
            Ok(decoded) => allow_credentials.push(decoded),
            Err(_) => {
                output_error(
                    ErrorCode::InvalidInput,
                    format!("Invalid base64 encoding for credential ID: {}", cred.id),
                );
                std::process::exit(1);
            }
        }
    }

    let timeout_ms = request.timeout.unwrap_or(60000);

    let result = match ctap::get_assertion(
        &request.rp_id,
        &client_data_json,
        &allow_credentials,
        request.pin.as_deref(),
        timeout_ms,
    ) {
        Ok(r) => r,
        Err(e) => {
            output_error(e.code(), e.to_string());
            std::process::exit(1);
        }
    };

    let response = AssertionResponse::new(
        request.challenge.clone(),
        request.rp_id.clone(),
        base64util::encode(&result.credential_id),
        base64util::encode(client_data_json.as_bytes()),
        base64util::encode(&result.authenticator_data),
        base64util::encode(&result.signature),
        result.user_handle.as_ref().map(|h| base64util::encode(h)),
    );

    output_success(response);
    Ok(())
}

fn output_error(code: ErrorCode, message: impl Into<String>) {
    let response = ErrorResponse::new(code, message);
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn output_success(response: AssertionResponse) {
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn print_help() {
    println!(
        r#"webauthn-assert v0.1.0

A CLI for WebAuthn security key assertions via CTAP2.

USAGE:
    echo '<json>' | webauthn-assert
    webauthn-assert --check
    webauthn-assert --help
    webauthn-assert --version

OPTIONS:
    --apple      Enforce Apple iCloud mode (rpId=apple.com, origin=https://apple.com)
    --check      Check if a security key is connected
    --help, -h   Show this help message
    --version, -v Show version

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
    Success: {{"ok":true,"challenge":"...","rpId":"...","credentialID":"...","clientData":"...","authenticatorData":"...","signatureData":"...","userHandle":"..."}}
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
"#
    );
}
