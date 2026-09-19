use crate::{
    DecodeError,
    codec::{Decoder, Encoder, KmDecode, KmEncode},
};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Aes = 0x01,
    Rsa = 0x02,
    Ec = 0x03,
    Hmac = 0x04,
}

impl TryFrom<u32> for KeyType {
    type Error = DecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Aes),
            0x02 => Ok(Self::Rsa),
            0x03 => Ok(Self::Ec),
            0x04 => Ok(Self::Hmac),
            _ => Err(DecodeError::UnexpectedPayload),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    Encrypt = 0x01,
    Sign = 0x02,
    Derive = 0x03,
}

impl TryFrom<u32> for KeyUsage {
    type Error = DecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Encrypt),
            0x02 => Ok(Self::Sign),
            0x03 => Ok(Self::Derive),
            _ => Err(DecodeError::InvalidArgument),
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyFilterFlags: u32 {
        const DEFAULT = 0;
        const LABEL = 1 << 0;
        const TYPE = 1 << 1;
        const USAGE = 1 << 2;
        const ID = 1 << 3;
    }
}

pub struct KeyMeta {
    pub id: u32,
    pub key_type: KeyType,
    pub key_usage: KeyUsage,
    pub size: u16,
    pub label: String,
    pub created_at: u32,
}

impl KmDecode<KeyMeta> for KeyMeta {
    fn decode(decoder: &mut Decoder) -> Result<Self, crate::DecodeError> {
        let id = decoder.read_u32()?;
        let key_type = KeyType::try_from(decoder.read_u32()?)?;
        let key_usage = KeyUsage::try_from(decoder.read_u32()?)?;
        let size = decoder.read_u16()?;
        let label = decoder.read_str()?.to_string();
        let created_at = decoder.read_u32()?;

        Ok(Self {
            id,
            key_type,
            key_usage,
            size,
            label,
            created_at,
        })
    }
}

pub struct KeyList {
    pub keys: Vec<KeyMeta>,
}

pub struct PublicKey {
    pub encoding: u32,
    pub public_key: Box<[u8]>,
}

impl KmDecode<PublicKey> for PublicKey {
    fn decode(decoder: &mut Decoder) -> Result<PublicKey, DecodeError> {
        let encoding = decoder.read_u32()?;
        let public_key_len = decoder.read_u32()?;
        let bytes = decoder.read_bytes(public_key_len as usize)?.to_vec();
        let public_key = bytes.into_boxed_slice();

        Ok(Self {
            encoding,
            public_key,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::protocol::{KmCommand, usb_decode_response};

    #[test]
    fn public_key_decode_owns_binary_bytes() {
        // Synthetic bytes exercise framing, not ASN.1/SPKI validation.
        let key = {
            let payload = vec![0, 0, 0, 1, 0, 0, 0, 4, 0x30, 0, 0x80, 0xFF];
            PublicKey::decode(&mut Decoder::new(&payload)).unwrap()
        };
        assert_eq!(key.encoding, 1);
        assert_eq!(&*key.public_key, &[0x30, 0, 0x80, 0xFF]);
    }

    #[test]
    fn public_key_rejects_truncation_and_impossible_byte_count() {
        let payload = [0, 0, 0, 1, 0, 0, 0, 4, 0x30, 0, 0x80, 0xFF];
        for end in 0..payload.len() {
            assert!(
                matches!(
                    PublicKey::decode(&mut Decoder::new(&payload[..end])),
                    Err(DecodeError::TruncatedPayload)
                ),
                "prefix length {end}"
            );
        }
        let payload = [0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(matches!(
            PublicKey::decode(&mut Decoder::new(&payload)),
            Err(DecodeError::TruncatedPayload)
        ));
    }

    // Firmware commands.c: count, then id/type/usage/size/label/created_at.
    // Independent golden bytes, not produced by the host encoder.
    fn one_key_payload() -> Vec<u8> {
        vec![
            0, 0, 0, 1, // count
            0x4B, 0x4D, 0x10, 0, // id
            0, 0, 0, 1, // AES
            0, 0, 0, 1, // Encrypt
            1, 0, // 256 bits
            0, 0, 0, 2, 0xC3, 0xA9, // UTF-8 label é
            1, 2, 3, 4, // timestamp
        ]
    }

    #[test]
    fn list_decodes_owned_metadata_from_golden_bytes() {
        let list = {
            let bytes = one_key_payload();
            KeyList::decode(&mut Decoder::new(&bytes)).unwrap()
        }; // The source buffer is gone; the returned label must remain valid.
        assert_eq!(list.keys.len(), 1);
        let key = &list.keys[0];
        assert_eq!(key.id, 0x4B4D1000);
        assert_eq!(key.key_type, KeyType::Aes);
        assert_eq!(key.key_usage, KeyUsage::Encrypt);
        assert_eq!(key.size, 256);
        assert_eq!(key.label, "é");
        assert_eq!(key.created_at, 0x01020304);
    }

    #[test]
    fn list_decodes_multiple_entries_using_one_cursor() {
        let mut bytes = one_key_payload();
        let second = bytes[4..].to_vec();
        bytes[3] = 2;
        bytes.extend_from_slice(&second);
        let mut decoder = Decoder::new(&bytes);
        let list = KeyList::decode(&mut decoder).unwrap();
        assert_eq!(list.keys.len(), 2);
        assert_eq!(list.keys[1].label, "é");
        assert!(decoder.is_empty());
    }

    #[test]
    fn list_decodes_zero_entries() {
        let list = KeyList::decode(&mut Decoder::new(&[0; 4])).unwrap();
        assert!(list.keys.is_empty());
    }

    #[test]
    fn list_rejects_every_truncated_prefix() {
        let bytes = one_key_payload();
        for end in 0..bytes.len() {
            assert!(
                matches!(
                    KeyList::decode(&mut Decoder::new(&bytes[..end])),
                    Err(DecodeError::TruncatedPayload)
                ),
                "accepted or misclassified truncated prefix of {end} bytes"
            );
        }
    }

    #[test]
    fn list_rejects_impossible_count_and_label_length() {
        assert!(matches!(
            KeyList::decode(&mut Decoder::new(&[0xFF; 4])),
            Err(DecodeError::TruncatedPayload)
        ));
        let mut bytes = one_key_payload();
        bytes[18..22].fill(0xFF);
        assert!(matches!(
            KeyList::decode(&mut Decoder::new(&bytes)),
            Err(DecodeError::TruncatedPayload)
        ));
    }

    #[test]
    fn list_rejects_invalid_utf8_and_unknown_enums() {
        let mut bytes = one_key_payload();
        bytes[22] = 0xFF;
        assert!(matches!(
            KeyList::decode(&mut Decoder::new(&bytes)),
            Err(DecodeError::InvalidUtf8)
        ));
        for offset in [11, 15] {
            let mut bytes = one_key_payload();
            bytes[offset] = 0xFE;
            assert!(KeyList::decode(&mut Decoder::new(&bytes)).is_err());
        }
    }

    #[test]
    fn list_response_rejects_unconsumed_payload_bytes() {
        // Declares zero entries, but has one unexplained payload byte.
        let frame = [0x4B, 0x4D, 0x47, 0x52, 1, 0x40, 0, 5, 0, 0, 0, 0, 0xAA];
        assert!(matches!(
            usb_decode_response::<KeyList>(KmCommand::ListKeys, &frame),
            Err(crate::EnigmaError::Protocol(DecodeError::UnexpectedPayload))
        ));
    }

    #[test]
    fn unfiltered_request_still_encodes_all_placeholders() {
        assert_eq!(KeyListFilter::default().encode(), vec![0; 20]);
    }

    #[test]
    fn combined_filters_encode_flags_and_wire_field_order() {
        let filter = KeyListFilter {
            key_type: Some(KeyType::Ec),
            key_usage: Some(KeyUsage::Derive),
            key_label: Some("é"),
            key_id: Some(0x01020304),
        };
        assert_eq!(
            filter.encode(),
            vec![
                0, 0, 0, 0x0F, // all four flags
                0, 0, 0, 3, // EC
                0, 0, 0, 3, // Derive
                0, 0, 0, 2, 0xC3, 0xA9, // label length is bytes
                1, 2, 3, 4, // id follows the label
            ]
        );
    }

    #[test]
    fn empty_label_and_zero_id_are_present_filters() {
        let filter = KeyListFilter {
            key_label: Some(""),
            key_id: Some(0),
            ..Default::default()
        };
        let mut expected = vec![0; 20];
        expected[3] = 0x09;
        assert_eq!(filter.encode(), expected);
    }
}

impl KmDecode<KeyList> for KeyList {
    fn decode(decoder: &mut Decoder) -> Result<KeyList, DecodeError> {
        let count = decoder.read_u32()?;

        let mut keys: Vec<KeyMeta> = vec![];

        for _ in 0..count {
            let key_meta = KeyMeta::decode(decoder)?;
            keys.push(key_meta);
        }

        Ok(Self { keys })
    }
}
