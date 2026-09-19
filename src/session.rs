use crate::codec::{Encoder, KmEncode};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{KmCommand, usb_encode_request};

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
}
