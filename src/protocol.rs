use crate::codec::{Decoder, Encoder};
use crate::error::{DecodeError, DeviceError, EnigmaError};
use crate::key::KeyFilterFlags;
use crate::{KeyType, KeyUsage};

#[derive(Clone, Copy, Debug)]
pub enum KmCommand {
    Status = 0x02,
    Authenticate = 0x11,
    Lock = 0x12,
    GetPublicKey = 0x30,
    ListKeys = 0x40,
}

impl KmCommand {
    fn expected_response(self) -> u8 {
        match self {
            Self::Status => 0x02,
            Self::Authenticate => 0x00,
            Self::Lock => 0x00,
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

pub(crate) trait KmEncode {
    fn encode(&self) -> Vec<u8>;
}

pub(crate) trait KmDecode<T> {
    fn decode(decoder: &mut Decoder) -> Result<T, DecodeError>;
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

pub struct AuthenticateRequest<'a> {
    pub pin: &'a str,
}

impl KmEncode for AuthenticateRequest<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.write_str(self.pin);
        encoder.bytes()
    }
}

#[derive(Default)]
pub struct KeyListFilter<'a> {
    pub key_type: Option<KeyType>,
    pub key_usage: Option<KeyUsage>,
    pub key_label: Option<&'a str>,
    pub key_id: Option<u32>,
}

impl KmEncode for KeyListFilter<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();

        let mut flags = KeyFilterFlags::DEFAULT;
        if self.key_type.is_some() {
            flags |= KeyFilterFlags::TYPE
        }
        if self.key_usage.is_some() {
            flags |= KeyFilterFlags::USAGE
        }
        if self.key_label.is_some() {
            flags |= KeyFilterFlags::LABEL
        }
        if self.key_id.is_some() {
            flags |= KeyFilterFlags::ID
        }

        encoder.write_u32(flags.bits());
        encoder.write_u32(self.key_type.map_or(0, |val| val as u32));
        encoder.write_u32(self.key_usage.map_or(0, |val| val as u32));
        encoder.write_str(self.key_label.unwrap_or(""));
        encoder.write_u32(self.key_id.unwrap_or(0));

        encoder.bytes()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct GetPublicKeyRequest {
    pub key_id: u32,
}

impl KmEncode for GetPublicKeyRequest {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.write_u32(self.key_id);
        encoder.bytes()
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

    // Golden frames follow firmware commands.c, serial.c, and usb_transport.c.
    // PINs below are dummy test data, never credentials from a real device.
    #[test]
    fn it_encodes_an_authentication_request() {
        let bytes =
            usb_encode_request(KmCommand::Authenticate, AuthenticateRequest { pin: "1234" });

        assert_eq!(
            bytes,
            [
                0x4B, 0x4D, 0x47, 0x52, // KMGR
                0x01, 0x11, 0x00, 0x08, // version, command, payload length
                0x00, 0x00, 0x00, 0x04, // PIN byte length (u32 big-endian)
                0x31, 0x32, 0x33, 0x34, // PIN bytes, without a NUL terminator
            ]
        );
    }

    #[test]
    fn it_encodes_pin_length_in_bytes_not_characters() {
        let bytes = usb_encode_request(KmCommand::Authenticate, AuthenticateRequest { pin: "é" });

        assert_eq!(
            bytes,
            [
                0x4B, 0x4D, 0x47, 0x52, 0x01, 0x11, 0x00, 0x06, 0x00, 0x00, 0x00,
                0x02, // One character, two UTF-8 bytes
                0xC3, 0xA9,
            ]
        );
    }

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
