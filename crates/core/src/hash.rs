use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_hex(raw: &str) -> Result<Self, ParseHexError> {
        Ok(Self(decode_hex_array(raw)?))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub fn hash256(data: &[u8]) -> Hash256 {
    let digest = blake3::hash(data);
    Hash256(*digest.as_bytes())
}

pub fn decode_hex_array<const N: usize>(raw: &str) -> Result<[u8; N], ParseHexError> {
    let normalized = raw.strip_prefix("0x").unwrap_or(raw);
    let decoded = hex::decode(normalized)?;
    if decoded.len() != N {
        return Err(ParseHexError::InvalidLength {
            expected_bytes: N,
            got_bytes: decoded.len(),
        });
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[derive(Debug, Error)]
pub enum ParseHexError {
    #[error("hex decode failed: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("hex has invalid byte length: expected {expected_bytes}, got {got_bytes}")]
    InvalidLength {
        expected_bytes: usize,
        got_bytes: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::{Hash256, hash256};

    #[test]
    fn hash_is_stable_for_same_input() {
        let first = hash256(b"SCAM");
        let second = hash256(b"SCAM");
        assert_eq!(first, second);
    }

    #[test]
    fn parse_and_format_roundtrip() {
        let expected = hash256(b"roundtrip");
        let parsed = Hash256::from_hex(&expected.to_hex()).expect("hash hex should parse");
        assert_eq!(expected, parsed);
    }
}
