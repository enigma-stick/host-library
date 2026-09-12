use std::fmt::Display;

use crate::codec::Decoder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceErrorCode {
    Ok = 0x00,
    AuthRequired = 0x01,
    AuthFailed = 0x02,
    InvalidInput = 0x03,
    UnsupportedOperation = 0x04,
    MissingKey = 0x05,
    PolicyReject = 0x06,
    Storage = 0x07,
    BadCommand = 0x08,
    Serialize = 0x09,
    InitFailed = 0x0A,
    InvalidState = 0x0B,
    Fail = 0xFF,
}

impl TryFrom<u8> for DeviceErrorCode {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Ok),
            0x01 => Ok(Self::AuthRequired),
            0x02 => Ok(Self::AuthFailed),
            0x03 => Ok(Self::InvalidInput),
            0x04 => Ok(Self::UnsupportedOperation),
            0x05 => Ok(Self::MissingKey),
            0x06 => Ok(Self::PolicyReject),
            0x07 => Ok(Self::Storage),
            0x08 => Ok(Self::BadCommand),
            0x09 => Ok(Self::Serialize),
            0x0A => Ok(Self::InitFailed),
            0x0B => Ok(Self::InvalidState),
            0xFF => Ok(Self::Fail),
            other => return Err(DecodeError::UnexpectedResponse(other)),
        }
    }
}

impl Display for DeviceErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => f.write_str("Ok"),
            Self::AuthRequired => f.write_str("Authentication required"),
            Self::AuthFailed => f.write_str("Authentication failed"),
            Self::InvalidInput => f.write_str("Invalid input"),
            Self::UnsupportedOperation => f.write_str("Unsupported operation"),
            Self::MissingKey => f.write_str("Missing key"),
            Self::PolicyReject => f.write_str("Policy rejection"),
            Self::Storage => f.write_str("Storage error"),
            Self::BadCommand => f.write_str("Bad command"),
            Self::Serialize => f.write_str("Serialization error"),
            Self::InitFailed => f.write_str("Initialization failed"),
            Self::InvalidState => f.write_str("Invalid state"),
            Self::Fail => f.write_str("Unknown error"),
        }
    }
}

#[derive(Debug)]
pub enum DecodeError {
    TruncatedHeader,
    TruncatedPayload,
    UnexpectedPayload,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnexpectedResponse(u8),
    InvalidTokenState(u32),
    InvalidSessionState(u32),
    InvalidUtf8,
    InvalidArgument,
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("Truncated header"),
            Self::TruncatedPayload => f.write_str("Truncated payload"),
            Self::UnexpectedPayload => f.write_str("Unexpected payload"),
            Self::InvalidMagic => f.write_str("Invalid header magic"),
            Self::UnsupportedVersion(v) => {
                write!(f, "Unsupported version: {:02X}", v)
            }
            Self::UnexpectedResponse(r) => {
                write!(f, "Unexpected response: {:02X}", r)
            }
            Self::InvalidTokenState(s) => {
                write!(f, "Invalid token state: {:02X}", s)
            }
            Self::InvalidSessionState(s) => {
                write!(f, "Invalid session state: {:02X}", s)
            }
            Self::InvalidUtf8 => f.write_str("Invalid UTF-8"),
            Self::InvalidArgument => f.write_str("Invalid argument"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug)]
pub struct DeviceError {
    pub code: DeviceErrorCode,
    pub message: String,
}

impl DeviceError {
    pub(crate) fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(payload);

        let code = DeviceErrorCode::try_from(decoder.read_u8()?)?;
        let message = decoder.read_str()?;

        Ok(Self {
            code: code,
            message: message.to_owned(),
        })
    }
}

impl Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(f, "{}", self.code)
        } else {
            write!(f, "{}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for DeviceError {}

#[derive(Debug)]
pub enum EnigmaError {
    Protocol(DecodeError),
    Device(DeviceError),
    Usb(rusb::Error),
    DeviceNotFound,
    MultipleDevicesFound,
    MissingInterface { interface: u8, alternate: u8 },
    MissingBulkEndpoint(u8),
    InvalidArgument,
    MalformedOutput,
}

impl From<DecodeError> for EnigmaError {
    fn from(value: DecodeError) -> Self {
        Self::Protocol(value)
    }
}

impl From<rusb::Error> for EnigmaError {
    fn from(value: rusb::Error) -> Self {
        Self::Usb(value)
    }
}

impl Display for EnigmaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "Protocol error: {error}"),
            Self::Device(error) => write!(f, "Device error: {error}"),
            Self::Usb(error) => write!(f, "USB error: {error}"),
            Self::DeviceNotFound => f.write_str("Device not found"),
            Self::MultipleDevicesFound => f.write_str("Multiple devices found"),
            Self::MissingInterface {
                interface,
                alternate,
            } => write!(
                f,
                "Missing interface: {:02X} / {:02X}",
                interface, alternate
            ),
            Self::MissingBulkEndpoint(endpoint) => {
                write!(f, "Missing bulk endpoint: {:02X}", endpoint)
            }
            Self::InvalidArgument => f.write_str("Invalid argument"),
            Self::MalformedOutput => f.write_str("Malformed output"),
        }
    }
}

impl std::error::Error for EnigmaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Device(error) => Some(error),
            Self::Usb(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{KmCommand, usb_decode_response};
    use crate::status::Status;

    #[test]
    fn it_decodes_an_error() {
        let bytes = [
            0x4B, 0x4D, 0x47, 0x52, // KMGR
            0x01, 0xFF, // version, error response
            0x00, 0x09, // payload length
            0x01, // code -> Authentication Required
            0x00, 0x00, 0x00, 0x04, // message length
            0x62, 0x61, 0x64, 0x21, // message -> 'bad!'
        ];
        let result = usb_decode_response::<Status>(KmCommand::Status, &bytes);

        assert!(matches!(
            result,
            Err(EnigmaError::Device(DeviceError {
                code: DeviceErrorCode::AuthRequired,
                message
            })) if message == "bad!"
        ));
    }
}
