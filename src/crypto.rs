use crate::codec::{Decoder, Encoder, KmDecode, KmEncode};
use crate::error::DecodeError;

pub struct SignRequest<'a> {
    pub key_id: u32,
    pub message: &'a [u8],
}

impl KmEncode for SignRequest<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.write_u32(self.key_id);
        encoder.write_bytes(self.message);
        encoder.bytes()
    }
}

pub struct VerifyRequest<'a> {
    pub key_id: u32,
    pub message: &'a [u8],
    pub signature: &'a [u8],
}

impl KmEncode for VerifyRequest<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.write_u32(self.key_id);
        encoder.write_bytes(self.message);
        encoder.write_bytes(self.signature);
        encoder.bytes()
    }
}

pub struct Signature {
    pub signature: Box<[u8]>,
}

impl KmDecode<Signature> for Signature {
    fn decode(decoder: &mut Decoder) -> Result<Signature, DecodeError> {
        let len = decoder.read_u32()?;
        let bytes = decoder.read_bytes(len as usize)?.to_vec();
        let signature = bytes.into_boxed_slice();

        Ok(Self { signature })
    }
}

pub struct EncryptRequest<'a> {
    pub key_id: u32,
    pub plaintext: &'a [u8],
}

impl KmEncode for EncryptRequest<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.write_u32(self.key_id);
        encoder.write_bytes(self.plaintext);
        encoder.bytes()
    }
}

pub struct DecryptRequest<'a> {
    pub key_id: u32,
    pub ciphertext: &'a [u8],
}

impl KmEncode for DecryptRequest<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.write_u32(self.key_id);
        encoder.write_bytes(self.ciphertext);
        encoder.bytes()
    }
}

pub struct EncryptDecryptResponse {
    pub data: Box<[u8]>,
}

impl KmDecode<EncryptDecryptResponse> for EncryptDecryptResponse {
    fn decode(decoder: &mut Decoder) -> Result<EncryptDecryptResponse, DecodeError> {
        let len = decoder.read_u32()?;
        let bytes = decoder.read_bytes(len as usize)?.to_vec();
        let data = bytes.into_boxed_slice();

        Ok(Self { data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{KmCommand, usb_encode_request};

    #[test]
    fn signing_request_matches_firmware_wire_order() {
        let request = SignRequest {
            key_id: 0x01020304,
            message: &[0, 0x80, 0xFF],
        };
        assert_eq!(
            usb_encode_request(KmCommand::Sign, request),
            vec![
                0x4B, 0x4D, 0x47, 0x52, 1, 0x23, 0, 11, 1, 2, 3, 4, // key id
                0, 0, 0, 3, // message byte length
                0, 0x80, 0xFF,
            ]
        );
    }
    #[test]
    fn signature_decode_owns_binary_output() {
        let signature = {
            let bytes = vec![0, 0, 0, 4, 0x30, 0, 0x80, 0xFF];
            Signature::decode(&mut Decoder::new(&bytes)).unwrap()
        };
        assert_eq!(&*signature.signature, &[0x30, 0, 0x80, 0xFF]);
    }

    #[test]
    fn signature_decode_rejects_truncation() {
        let bytes = [0, 0, 0, 4, 0x30, 0, 0x80, 0xFF];
        for end in 0..bytes.len() {
            assert!(
                matches!(
                    Signature::decode(&mut Decoder::new(&bytes[..end])),
                    Err(DecodeError::TruncatedPayload)
                ),
                "prefix length {end}"
            );
        }
    }
}
