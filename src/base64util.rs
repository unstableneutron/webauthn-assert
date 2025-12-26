use base64::{engine::general_purpose, Engine};

pub fn decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let normalized = input.replace('-', "+").replace('_', "/");

    let padded = match normalized.len() % 4 {
        2 => format!("{}==", normalized),
        3 => format!("{}=", normalized),
        _ => normalized,
    };

    general_purpose::STANDARD.decode(&padded)
}

pub fn encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64url() {
        let input = "SGVsbG8gV29ybGQ";
        let result = decode(input).unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn test_decode_base64_standard() {
        let input = "SGVsbG8gV29ybGQ=";
        let result = decode(input).unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn test_decode_with_url_safe_chars() {
        let input = "PDw_Pz4-";
        let result = decode(input).unwrap();
        assert_eq!(result, b"<<??>>");
    }

    #[test]
    fn test_encode_standard() {
        let data = b"Hello World";
        let result = encode(data);
        assert_eq!(result, "SGVsbG8gV29ybGQ=");
    }
}
