use crate::error::DecodeError;

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        if count > self.bytes.len() - self.position {
            return Err(DecodeError::TruncatedPayload);
        }

        let end = self.position + count;
        let return_bytes = &self.bytes[self.position..end];
        self.position += count;
        Ok(return_bytes)
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.take(2)?;
        let array: [u8; 2] = bytes
            .try_into()
            .map_err(|_| DecodeError::TruncatedPayload)?;
        Ok(u16::from_be_bytes(array))
    }

    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let bytes = self.take(4)?;
        let array: [u8; 4] = bytes
            .try_into()
            .map_err(|_| DecodeError::TruncatedPayload)?;
        Ok(u32::from_be_bytes(array))
    }

    pub fn read_str(&mut self) -> Result<&'a str, DecodeError> {
        let str_len = self.read_u32()?;
        let str_bytes = self.take(str_len as usize)?;
        let result = str::from_utf8(str_bytes).map_err(|_| DecodeError::InvalidUtf8)?;
        Ok(result)
    }
}
