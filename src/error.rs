use crate::models::ErrorCode;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum WebAuthnError {
    #[error("No security key detected. Please insert your security key.")]
    NoDevice,

    #[error("No matching credentials found on the security key.")]
    NoCredentials,

    #[error("User did not touch the security key within the timeout period.")]
    UserCanceled,

    #[error("Security key requires a PIN. Please provide the PIN.")]
    PinRequired,

    #[error("The provided PIN is incorrect.")]
    PinInvalid,

    #[error("PIN is blocked due to too many incorrect attempts.")]
    PinBlocked,

    #[error("Operation timed out.")]
    Timeout,

    #[error("Multiple security keys detected. Please ensure only one key is connected.")]
    MultipleDevices,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("CTAP error: {0}")]
    Ctap(String),

    #[error("Unexpected error: {0}")]
    Unknown(String),
}

impl WebAuthnError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::NoDevice => ErrorCode::NoDevice,
            Self::NoCredentials => ErrorCode::NoCredentials,
            Self::UserCanceled => ErrorCode::UserCanceled,
            Self::PinRequired => ErrorCode::PinRequired,
            Self::PinInvalid => ErrorCode::PinInvalid,
            Self::PinBlocked => ErrorCode::PinBlocked,
            Self::Timeout => ErrorCode::Timeout,
            Self::MultipleDevices => ErrorCode::MultipleDevices,
            Self::InvalidInput(_) => ErrorCode::InvalidInput,
            Self::Ctap(_) | Self::Unknown(_) => ErrorCode::Unknown,
        }
    }
}
