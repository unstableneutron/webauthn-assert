# webauthn-assert

A cross-platform CLI for WebAuthn security key assertions via CTAP2.

This tool enables applications to authenticate using hardware security keys (YubiKey, SoloKey, etc.) by bridging the CTAP2 protocol to WebAuthn-formatted responses.

## Requirements

- USB/NFC security key (YubiKey 5, SoloKey, Nitrokey, etc.)

### Platform-specific

| Platform | Requirements |
|----------|--------------|
| **Linux** | `sudo apt install libusb-1.0-0-dev libudev-dev` |
| **Windows** | Run as Administrator |
| **macOS** | No special requirements |

## Installation

### From crates.io

```bash
cargo install webauthn-assert
```

### From source

```bash
git clone https://github.com/unstableneutron/webauthn-assert.git
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

## Input Format

JSON provided via stdin:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rpId` | string | Yes | Relying party identifier (domain only, not URL) |
| `challenge` | string | Yes | Base64 or base64url encoded challenge |
| `origin` | string | Yes | Origin for clientDataJSON (e.g., `https://example.com`) |
| `allowCredentials` | array | No | List of credential descriptors |
| `pin` | string | No | Security key PIN if required |
| `timeout` | number | No | Timeout in milliseconds (default: 60000) |

### Credential Descriptor

```json
{"id": "base64-credential-id", "transports": ["usb", "nfc"]}
```

## Output Format

### Success

```json
{
  "ok": true,
  "credentialId": "base64-encoded",
  "clientDataJSON": "base64-encoded",
  "authenticatorData": "base64-encoded",
  "signature": "base64-encoded",
  "userHandle": "base64-encoded"
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

## Error Codes

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

Reload rules:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Windows

Must run with Administrator privileges for USB HID access.

### macOS

No special configuration required.

## License

MIT
