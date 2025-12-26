use crate::error::WebAuthnError;
use ctap_hid_fido2::{
    fidokey::GetAssertionArgsBuilder, get_fidokey_devices, Cfg, FidoKeyHid, FidoKeyHidFactory,
};

pub struct AssertionResult {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

pub fn enumerate_devices() -> Result<String, WebAuthnError> {
    let devices = get_fidokey_devices();
    if devices.is_empty() {
        return Err(WebAuthnError::NoDevice);
    }
    if devices.len() > 1 {
        return Err(WebAuthnError::MultipleDevices);
    }
    let first = &devices[0];
    let name = if first.info.is_empty() {
        format!("FIDO Device {:04x}:{:04x}", first.vid, first.pid)
    } else {
        first.info.clone()
    };
    Ok(name)
}

pub fn get_assertion(
    rp_id: &str,
    client_data_json: &str,
    allow_credentials: &[Vec<u8>],
    pin: Option<&str>,
    _timeout_ms: u64,
) -> Result<AssertionResult, WebAuthnError> {
    let device = create_device()?;

    let mut builder = GetAssertionArgsBuilder::new(rp_id, client_data_json.as_bytes());

    for cred_id in allow_credentials {
        builder = builder.add_credential_id(cred_id);
    }

    builder = match pin {
        Some(p) => builder.pin(p),
        None => builder.without_pin_and_uv(),
    };

    let args = builder.build();

    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(map_ctap_error)?;

    let assertion = assertions
        .into_iter()
        .next()
        .ok_or(WebAuthnError::NoCredentials)?;

    let credential_id = if assertion.credential_id.is_empty() {
        return Err(WebAuthnError::NoCredentials);
    } else {
        assertion.credential_id.clone()
    };

    let user_handle = if assertion.user.id.is_empty() {
        None
    } else {
        Some(assertion.user.id.clone())
    };

    Ok(AssertionResult {
        credential_id,
        authenticator_data: assertion.auth_data.clone(),
        signature: assertion.signature.clone(),
        user_handle,
    })
}

fn create_device() -> Result<FidoKeyHid, WebAuthnError> {
    match FidoKeyHidFactory::create(&Cfg::init()) {
        Ok(d) => Ok(d),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("Multiple") {
                return Err(WebAuthnError::MultipleDevices);
            }
            Err(WebAuthnError::NoDevice)
        }
    }
}

fn map_ctap_error(e: anyhow::Error) -> WebAuthnError {
    let err_str = e.to_string().to_lowercase();

    if err_str.contains("no credential") || err_str.contains("no credentials") {
        return WebAuthnError::NoCredentials;
    }
    if err_str.contains("pin required") || err_str.contains("pin_required") {
        return WebAuthnError::PinRequired;
    }
    if err_str.contains("pin invalid") || err_str.contains("pin_invalid") {
        return WebAuthnError::PinInvalid;
    }
    if err_str.contains("pin blocked") || err_str.contains("pin_blocked") {
        return WebAuthnError::PinBlocked;
    }
    if err_str.contains("timeout") || err_str.contains("timed out") {
        return WebAuthnError::Timeout;
    }
    if err_str.contains("cancel") || err_str.contains("user presence") {
        return WebAuthnError::UserCanceled;
    }
    if err_str.contains("not found") || err_str.contains("no device") {
        return WebAuthnError::NoDevice;
    }

    WebAuthnError::Ctap(e.to_string())
}
