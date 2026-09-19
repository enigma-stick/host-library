use crate::codec::{Decoder, KmDecode, KmEncode};
use crate::error::{DecodeError, DeviceError, EnigmaError};

#[derive(Clone, Copy, Debug)]
pub enum KmCommand {
    Status = 0x02,
    Authenticate = 0x11,
    Lock = 0x12,
    Encrypt = 0x21,
    Decrypt = 0x22,
    Sign = 0x23,
    Verify = 0x24,
    GetPublicKey = 0x30,
    ListKeys = 0x40,
}

impl KmCommand {
    fn expected_response(self) -> u8 {
        match self {
            Self::Status => 0x02,
            Self::Authenticate => 0x00,
            Self::Lock => 0x00,
            Self::Encrypt => 0x21,
            Self::Decrypt => 0x22,
            Self::Sign => 0x23,
            Self::Verify => 0x24,
            Self::GetPublicKey => 0x30,
            Self::ListKeys => 0x40,
        }
    }
}

#[derive(Debug)]
pub struct KmFrameHeader {
    pub magic: u32,
    pub version: u8,
    pub command: u8,
    pub length: u16,
}

impl KmFrameHeader {
    pub fn default() -> Self {
        Self {
            magic: 0x4B4D4752,
            version: 0x1,
            command: 0xFF,
            length: 0,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let magic_bytes = self.magic.to_be_bytes().to_vec();
        let version_bytes = self.version.to_be_bytes().to_vec();
        let command_bytes = (self.command as u8).to_be_bytes().to_vec();
        let length_bytes = self.length.to_be_bytes().to_vec();

        [magic_bytes, version_bytes, command_bytes, length_bytes].concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);

        let magic = decoder.read_u32()?;
        let version = decoder.read_u8()?;
        let command = decoder.read_u8()?;
        let length = decoder.read_u16()?;

        if magic != 0x4B4D4752 {
            return Err(DecodeError::InvalidMagic);
        }

        if version != 1 {
            return Err(DecodeError::UnsupportedVersion(version));
        }

        Ok(Self {
            magic,
            version,
            command,
            length,
        })
    }
}

pub struct EmptyRequest {}
impl KmEncode for EmptyRequest {
    fn encode(&self) -> Vec<u8> {
        vec![]
    }
}

impl KmDecode<()> for () {
    fn decode(decoder: &mut Decoder) -> Result<(), DecodeError> {
        if !decoder.is_empty() {
            return Err(DecodeError::UnexpectedPayload);
        }

        Ok(())
    }
}

pub fn usb_encode_request<T: KmEncode>(command: KmCommand, request: T) -> Vec<u8> {
    let payload_bytes = request.encode();
    let payload_length = payload_bytes.len();

    let mut frame_header = KmFrameHeader::default();
    frame_header.length = payload_length as u16;
    frame_header.command = command as u8;
    let frame_header_bytes = frame_header.encode();

    [frame_header_bytes, payload_bytes].concat()
}

pub fn usb_decode_response<T: KmDecode<T>>(
    expected: KmCommand,
    response: &[u8],
) -> Result<T, EnigmaError> {
    if response.len() < 8 {
        return Err(EnigmaError::Protocol(DecodeError::TruncatedHeader));
    }

    let header_bytes = &response[0..8];
    let frame_header = KmFrameHeader::decode(&header_bytes)?;

    let end = usize::from(frame_header.length) + 8;
    if response.len() < end {
        return Err(EnigmaError::Protocol(DecodeError::TruncatedPayload));
    }
    let payload_bytes = &response[8..end];

    if frame_header.command != expected.expected_response() as u8 {
        if frame_header.command == 0xFF {
            let decoded_error = DeviceError::decode(&payload_bytes)?;
            return Err(EnigmaError::Device(decoded_error));
        } else {
            return Err(EnigmaError::Protocol(DecodeError::UnexpectedResponse(
                frame_header.command,
            )));
        }
    }

    let mut decoder = Decoder::new(payload_bytes);
    let decoded = T::decode(&mut decoder)?;

    if !decoder.is_empty() {
        return Err(EnigmaError::Protocol(DecodeError::UnexpectedPayload));
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::error::DeviceErrorCode;
    use crate::status::Status;

    #[test]
    fn it_decodes_an_empty_authentication_success() {
        let bytes = [0x4B, 0x4D, 0x47, 0x52, 0x01, 0x00, 0x00, 0x00];

        usb_decode_response::<()>(KmCommand::Authenticate, &bytes)
            .expect("authentication succeeds with response 0x00 and no payload");
    }

    #[test]
    fn it_rejects_a_nonempty_authentication_success() {
        let bytes = [0x4B, 0x4D, 0x47, 0x52, 0x01, 0x00, 0x00, 0x01, 0x42];
        let result = usb_decode_response::<()>(KmCommand::Authenticate, &bytes);

        assert!(
            matches!(
                result,
                Err(EnigmaError::Protocol(DecodeError::UnexpectedPayload))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn it_rejects_a_status_response_during_authentication() {
        let bytes = [
            0x4B, 0x4D, 0x47, 0x52, 0x01, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, // Ready
            0x00, 0x00, 0x00, 0x01, // Authenticated
        ];
        let result = usb_decode_response::<()>(KmCommand::Authenticate, &bytes);

        assert!(
            matches!(
                result,
                Err(EnigmaError::Protocol(DecodeError::UnexpectedResponse(0x02)))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn it_rejects_an_authentication_command_id_as_a_success_response() {
        let bytes = [0x4B, 0x4D, 0x47, 0x52, 0x01, 0x11, 0x00, 0x00];
        let result = usb_decode_response::<()>(KmCommand::Authenticate, &bytes);

        assert!(
            matches!(
                result,
                Err(EnigmaError::Protocol(DecodeError::UnexpectedResponse(0x11)))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn it_rejects_a_generic_ok_response_for_status() {
        let bytes = [0x4B, 0x4D, 0x47, 0x52, 0x01, 0x00, 0x00, 0x00];
        let result = usb_decode_response::<Status>(KmCommand::Status, &bytes);

        assert!(
            matches!(
                result,
                Err(EnigmaError::Protocol(DecodeError::UnexpectedResponse(0x00)))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn it_decodes_a_device_error_during_authentication() {
        let bytes = [
            0x4B, 0x4D, 0x47, 0x52, 0x01, 0xFF, 0x00, 0x09, 0x02, // Authentication failed
            0x00, 0x00, 0x00, 0x04, // Message byte length
            b'b', b'a', b'd', b'!',
        ];
        let result = usb_decode_response::<()>(KmCommand::Authenticate, &bytes);

        assert!(
            matches!(
                &result,
                Err(EnigmaError::Device(DeviceError {
                    code: DeviceErrorCode::AuthFailed,
                    message,
                })) if message == "bad!"
            ),
            "{result:?}"
        );
    }

    #[test]
    fn it_encodes() {
        let bytes = usb_encode_request(KmCommand::Status, EmptyRequest {});
        assert_eq!(bytes, [0x4B, 0x4D, 0x47, 0x52, 0x01, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn it_rejects_an_empty_status_payload() {
        let bytes = [
            0x4B, 0x4D, 0x47, 0x52, // KMGR
            0x01, 0x02, // version, status response
            0x00, 0x00, // zero payload bytes
        ];

        let result = usb_decode_response::<Status>(KmCommand::Status, &bytes);

        assert!(matches!(
            result,
            Err(EnigmaError::Protocol(DecodeError::TruncatedPayload))
        ));
    }
}
