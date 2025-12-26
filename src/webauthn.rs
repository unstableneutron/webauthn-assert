use crate::base64util;
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
        challenge: base64util::encode_url_no_pad(challenge_bytes),
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
    fn test_challenge_base64url_no_pad_encoded() {
        let challenge = b"\x00\x01\x02\x03";
        let json = build_client_data_json(challenge, "https://example.com");

        let expected_challenge = base64util::encode_url_no_pad(challenge);
        assert!(json.contains(&format!(r#""challenge":"{}""#, expected_challenge)));
        assert!(!expected_challenge.contains('+'));
        assert!(!expected_challenge.contains('/'));
        assert!(!expected_challenge.contains('='));
    }

    #[test]
    fn test_challenge_with_special_chars() {
        let challenge = b"\xfb\xe8\x60\xac\x98\x25\x31\x29";
        let json = build_client_data_json(challenge, "https://apple.com");

        assert!(
            json.contains(r#""challenge":"-"#)
                || json.contains(r#""challenge":"_"#)
                || !json.contains('+')
        );
        assert!(!json.contains("==\""));
    }
}
