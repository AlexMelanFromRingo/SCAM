#[derive(Default)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub fn write_varint(&mut self, value: usize) {
        let value = value as u64;
        if value < 0xfd {
            self.write_u8(value as u8);
            return;
        }
        if value <= 0xffff {
            self.write_u8(0xfd);
            self.bytes.extend_from_slice(&(value as u16).to_le_bytes());
            return;
        }
        if value <= 0xffff_ffff {
            self.write_u8(0xfe);
            self.bytes.extend_from_slice(&(value as u32).to_le_bytes());
            return;
        }
        self.write_u8(0xff);
        self.write_u64(value);
    }

    pub fn write_len_prefixed_bytes(&mut self, data: &[u8]) {
        self.write_varint(data.len());
        self.write_bytes(data);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::Encoder;

    #[test]
    fn varint_encoding_smoke() {
        let mut enc = Encoder::default();
        enc.write_varint(1);
        enc.write_varint(0xfd);
        enc.write_varint(70_000);
        let data = enc.into_bytes();
        assert!(!data.is_empty());
    }
}
