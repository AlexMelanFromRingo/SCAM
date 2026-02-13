use std::fmt;

use ripemd::{Digest, Ripemd160};
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

pub fn tagged_hash256(tag: &[u8], data: &[u8]) -> Hash256 {
    let tag_hash = blake3::hash(tag);
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag_hash.as_bytes());
    hasher.update(tag_hash.as_bytes());
    hasher.update(data);
    Hash256(*hasher.finalize().as_bytes())
}

pub fn hash160_blake3(data: &[u8]) -> [u8; 20] {
    let digest = blake3::hash(data);
    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(digest.as_bytes());
    let reduced = ripemd160.finalize();

    let mut out = [0u8; 20];
    out.copy_from_slice(&reduced);
    out
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
    use super::{Hash256, hash160_blake3, hash256, tagged_hash256};
    use proptest::prelude::*;

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

    #[test]
    fn tagged_hash_changes_with_tag() {
        let a = tagged_hash256(b"scam-tag-a", b"payload");
        let b = tagged_hash256(b"scam-tag-b", b"payload");
        assert_ne!(a, b);
    }

    #[test]
    fn hash160_blake3_is_stable() {
        let a = hash160_blake3(b"payload");
        let b = hash160_blake3(b"payload");
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 20]);
        assert_ne!(a, [1u8; 20]);
    }

    #[test]
    fn hash_display_is_hex_encoded() {
        let hash = hash256(b"display");
        let rendered = format!("{hash}");
        assert_eq!(rendered, hash.to_hex());
        assert_eq!(rendered.len(), 64);
    }

    proptest! {
        #[test]
        fn hash256_hex_roundtrip_proptest(raw in prop::array::uniform32(any::<u8>())) {
            let hash = Hash256(raw);
            let encoded = hash.to_hex();
            let decoded = Hash256::from_hex(&encoded).expect("hex roundtrip");
            prop_assert_eq!(decoded, hash);
        }
    }
}
