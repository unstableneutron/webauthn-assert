use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionRequest {
    pub rp_id: String,
    pub challenge: String,
    pub origin: String,
    #[serde(default)]
    pub allow_credentials: Vec<CredentialDescriptor>,
    pub pin: Option<String>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct CredentialDescriptor {
    pub id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub transports: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AssertionResponse {
    pub ok: bool,
    pub challenge: String,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(rename = "clientData")]
    pub client_data: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "signatureData")]
    pub signature_data: String,
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

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
    MultipleDevices,
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
            Self::MultipleDevices => "multiple_devices",
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
        challenge: String,
        rp_id: String,
        credential_id: String,
        client_data: String,
        authenticator_data: String,
        signature_data: String,
        user_handle: Option<String>,
    ) -> Self {
        Self {
            ok: true,
            challenge,
            rp_id,
            credential_id,
            client_data,
            authenticator_data,
            signature_data,
            user_handle,
        }
    }
}
