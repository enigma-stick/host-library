use crate::codec::Decoder;

#[derive(Debug)]
pub enum DeviceError {
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

impl TryFrom<u8> for DeviceError {
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

#[derive(Debug)]
pub enum EnigmaError {
    Protocol(DecodeError),
    Device(KmDeviceError),
    Usb(rusb::Error),
    DeviceNotFound,
    MultipleDevicesFound,
    MissingInterface { interface: u8, alternate: u8 },
    MissingBulkEndpoint(u8),
}

#[derive(Debug)]
pub enum DecodeError {
    TruncatedHeader,
    TruncatedPayload,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnexpectedResponse(u8),
    InvalidTokenState(u32),
    InvalidSessionState(u32),
    InvalidUtf8,
}

#[derive(Debug)]
pub struct KmDeviceError {
    code: DeviceError,
    message: String,
}

impl KmDeviceError {
    pub(crate) fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(payload);

        let code = DeviceError::try_from(decoder.read_u8()?)?;
        let message = decoder.read_str()?;

        Ok(Self {
            code: code,
            message: message.to_owned(),
        })
    }
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
            Err(EnigmaError::Device(KmDeviceError {
                code: DeviceError::AuthRequired,
                message
            })) if message == "bad!"
        ));
    }
}
