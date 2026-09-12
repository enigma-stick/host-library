use crate::codec::Decoder;
use crate::error::DecodeError;
use crate::protocol::KmDecode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    Uninitialized = 0x0,
    Provisioning = 0x1,
    Ready = 0x2,
}

impl TryFrom<u32> for TokenState {
    type Error = DecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Uninitialized),
            1 => Ok(Self::Provisioning),
            2 => Ok(Self::Ready),
            other => Err(DecodeError::InvalidTokenState(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Closed = 0x0,
    Authenticated = 0x1,
    Fault = 0x2,
}

impl TryFrom<u32> for SessionState {
    type Error = DecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Closed),
            1 => Ok(Self::Authenticated),
            2 => Ok(Self::Fault),
            other => Err(DecodeError::InvalidSessionState(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub token: TokenState,
    pub session: SessionState,
}

impl KmDecode<Status> for Status {
    fn decode(decoder: &mut Decoder) -> Result<Self, DecodeError> {
        let token = TokenState::try_from(decoder.read_u32()?)?;
        let session = SessionState::try_from(decoder.read_u32()?)?;

        Ok(Self { token, session })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{KmCommand, usb_decode_response};

    #[test]
    fn it_decodes() {
        let mut bytes: Vec<u8> = vec![0x4B, 0x4D, 0x47, 0x52, 0x01, 0x02, 0x00, 0x08];

        let token_bytes = (TokenState::Ready as u32).to_be_bytes().to_vec();
        let session_bytes = (SessionState::Authenticated as u32).to_be_bytes().to_vec();

        bytes = [bytes, token_bytes, session_bytes].concat();
        let status: Status = usb_decode_response(KmCommand::Status, bytes.as_slice()).unwrap();
        assert!(matches!(status.token, TokenState::Ready), "{status:?}");
        assert!(
            matches!(status.session, SessionState::Authenticated),
            "{status:?}"
        );
    }
}
