use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: String,
    pub cross_origin: bool,
}

pub fn build_client_data_json(challenge_bytes: &[u8], origin: &str) -> String {
    let client_data = ClientData {
        type_: "webauthn.get".to_string(),
        challenge: STANDARD.encode(challenge_bytes),
        origin: origin.to_string(),
        cross_origin: false,
    };
    serde_json::to_string(&client_data).expect("ClientData serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client_data_json_format() {
        let challenge = b"test-challenge";
        let origin = "https://example.com";
        let json = build_client_data_json(challenge, origin);

        assert!(json.contains(r#""type":"webauthn.get""#));
        assert!(json.contains(r#""origin":"https://example.com""#));
        assert!(json.contains(r#""crossOrigin":false"#));
    }

    #[test]
    fn test_challenge_base64_standard_encoded() {
        let challenge = b"\x00\x01\x02\x03";
        let json = build_client_data_json(challenge, "https://example.com");

        let expected_challenge = STANDARD.encode(challenge);
        assert!(json.contains(&format!(r#""challenge":"{}""#, expected_challenge)));
    }
}
