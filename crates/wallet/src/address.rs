use bech32::{FromBase32, ToBase32, Variant};
use scam_core::hash160_blake3;
use secp256k1::PublicKey;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedAddress {
    pub hrp: String,
    pub key_hash20: [u8; 20],
}

pub fn key_hash20_from_compressed_pubkey(
    pubkey_compressed: [u8; 33],
) -> Result<[u8; 20], AddressError> {
    let _ = PublicKey::from_slice(&pubkey_compressed).map_err(AddressError::InvalidPubkey)?;
    Ok(hash160_blake3(&pubkey_compressed))
}

pub fn to_address(hrp: &str, pubkey_compressed: [u8; 33]) -> Result<String, AddressError> {
    if hrp.trim().is_empty() {
        return Err(AddressError::InvalidHrp);
    }
    if !hrp.starts_with('s') {
        return Err(AddressError::InvalidHrpPrefix {
            expected_prefix: 's',
            got: hrp.to_owned(),
        });
    }
    let key_hash20 = key_hash20_from_compressed_pubkey(pubkey_compressed)?;
    bech32::encode(hrp, key_hash20.to_base32(), Variant::Bech32m).map_err(AddressError::Bech32)
}

pub fn parse_address(address: &str) -> Result<DecodedAddress, AddressError> {
    let (hrp, data, variant) = bech32::decode(address).map_err(AddressError::Bech32)?;
    if variant != Variant::Bech32m {
        return Err(AddressError::WrongVariant {
            expected: "Bech32m",
        });
    }
    if !hrp.starts_with('s') {
        return Err(AddressError::InvalidHrpPrefix {
            expected_prefix: 's',
            got: hrp,
        });
    }

    let decoded = Vec::<u8>::from_base32(&data).map_err(AddressError::Bech32)?;
    if decoded.len() != 20 {
        return Err(AddressError::InvalidPayloadLength {
            expected: 20,
            got: decoded.len(),
        });
    }
    let mut key_hash20 = [0u8; 20];
    key_hash20.copy_from_slice(&decoded);
    Ok(DecodedAddress { hrp, key_hash20 })
}

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("invalid pubkey bytes: {0}")]
    InvalidPubkey(#[source] secp256k1::Error),
    #[error("hrp is empty")]
    InvalidHrp,
    #[error("hrp must start with '{expected_prefix}', got '{got}'")]
    InvalidHrpPrefix { expected_prefix: char, got: String },
    #[error("bech32 error: {0}")]
    Bech32(#[source] bech32::Error),
    #[error("wrong bech32 variant: expected {expected}")]
    WrongVariant { expected: &'static str },
    #[error("invalid payload length: expected {expected}, got {got}")]
    InvalidPayloadLength { expected: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use scam_core::hash160_blake3;

    use crate::address::{key_hash20_from_compressed_pubkey, parse_address, to_address};
    use crate::signer::derive_wallet_key;

    #[test]
    fn address_encode_decode_roundtrip() {
        let seed = [42u8; 64];
        let key = derive_wallet_key(&seed, 0, 0).expect("derivation");
        let address = to_address("sd", key.pubkey_compressed()).expect("address encode");
        let decoded = parse_address(&address).expect("address decode");
        assert_eq!(decoded.hrp, "sd");
        assert_eq!(decoded.key_hash20, hash160_blake3(&key.pubkey_compressed()));
    }

    #[test]
    fn address_rejects_non_s_prefix_hrp() {
        let seed = [7u8; 64];
        let key = derive_wallet_key(&seed, 0, 0).expect("derivation");
        let err = to_address("abc", key.pubkey_compressed()).expect_err("must reject");
        assert!(matches!(
            err,
            crate::address::AddressError::InvalidHrpPrefix { .. }
        ));
    }

    #[test]
    fn key_hash20_matches_hash160_blake3_for_compressed_pubkey() {
        let seed = [9u8; 64];
        let key = derive_wallet_key(&seed, 0, 0).expect("derivation");
        let expected = hash160_blake3(&key.pubkey_compressed());
        let actual =
            key_hash20_from_compressed_pubkey(key.pubkey_compressed()).expect("key hash20");
        assert_eq!(actual, expected);
    }
}
