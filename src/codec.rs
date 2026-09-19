use crate::error::DecodeError;

pub(crate) trait KmEncode {
    fn encode(&self) -> Vec<u8>;
}

pub(crate) trait KmDecode<T> {
    fn decode(decoder: &mut Decoder) -> Result<T, DecodeError>;
}

impl KmDecode<bool> for bool {
    fn decode(decoder: &mut Decoder) -> Result<bool, DecodeError> {
        let value = decoder.read_u8()?;
        Ok(value != 0)
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

#[allow(dead_code)]
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

    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        self.take(count)
    }

    pub fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

impl Encoder {
    pub fn new() -> Self {
        Self { bytes: vec![] }
    }

    #[allow(dead_code)]
    pub fn write_u8(&mut self, data: u8) {
        self.bytes.push(data)
    }

    #[allow(dead_code)]
    pub fn write_u16(&mut self, data: u16) {
        let mut bytes = data.to_be_bytes().to_vec();
        self.bytes.append(&mut bytes);
    }

    pub fn write_u32(&mut self, data: u32) {
        let mut bytes = data.to_be_bytes().to_vec();
        self.bytes.append(&mut bytes);
    }

    pub fn write_str(&mut self, data: &str) {
        let str_len = data.len();
        self.write_u32(str_len as u32);
        self.bytes.extend_from_slice(data.as_bytes());
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        self.write_u32(data.len() as u32);
        self.bytes.extend_from_slice(data);
    }

    pub fn bytes(self) -> Vec<u8> {
        self.bytes
    }
}
