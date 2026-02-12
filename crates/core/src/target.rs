use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::{Hash256, ParseHexError, decode_hex_array};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Target(pub [u8; 32]);

impl Target {
    pub const MAX: Self = Self([0xff; 32]);
    pub const MIN: Self = Self([0x00; 32]);

    pub fn from_hex(raw: &str) -> Result<Self, ParseHexError> {
        Ok(Self(decode_hex_array(raw)?))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn allows_hash(&self, hash: &Hash256) -> bool {
        hash.0 <= self.0
    }
}

impl Default for Target {
    fn default() -> Self {
        Self::MAX
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use crate::{Hash256, Target};
    use proptest::prelude::*;

    #[test]
    fn numeric_compare_is_hash_lte_target() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target must parse");
        let lower =
            Hash256::from_hex("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("hash must parse");
        let higher =
            Hash256::from_hex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("hash must parse");

        assert!(target.allows_hash(&lower));
        assert!(!target.allows_hash(&higher));
    }

    proptest! {
        #[test]
        fn allows_hash_matches_numeric_compare(
            target_raw in prop::array::uniform32(any::<u8>()),
            hash_raw in prop::array::uniform32(any::<u8>())
        ) {
            let target = Target(target_raw);
            let hash = Hash256(hash_raw);
            prop_assert_eq!(target.allows_hash(&hash), hash_raw <= target_raw);
        }
    }
}
