use bech32::{FromBase32, ToBase32, Variant};
use scam_core::hash160_blake3;
use secp256k1::PublicKey;
use thiserror::Error;

/// Address kind. P2PKH is the legacy 33-byte-pubkey-hash style.
/// MultiSig encodes the same 20-byte hash but tags the data payload
/// with a leading discriminator byte so wallets render and route them
/// differently. Consensus does not care about the encoding; this is
/// purely a display/UX layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressKind {
    P2pkh,
    MultiSig,
}

/// Leading byte of the bech32m data payload that distinguishes a
/// multisig address from the legacy P2PKH form. Chosen as `0xCA` to
/// avoid colliding with any 5-bit-group prefix that a P2PKH payload
/// could naturally start with (P2PKH payload is exactly 20 raw bytes
/// → 32 base32 chars; multisig is 21 raw bytes = 0xCA tag + 20-byte
/// hash → 34 base32 chars, so the *length* alone disambiguates, but
/// the explicit tag is belt-and-suspenders).
pub const MULTISIG_ADDRESS_DISCRIMINATOR: u8 = 0xCA;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedAddress {
    pub hrp: String,
    pub key_hash20: [u8; 20],
    pub kind: AddressKind,
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

/// Encode a multisig script-hash as a bech32m address. The payload is
/// `MULTISIG_ADDRESS_DISCRIMINATOR || script_hash20`, so the resulting
/// address visibly differs in length AND first data character from
/// the legacy P2PKH form even when the HRP is identical.
pub fn to_multisig_address(hrp: &str, script_hash20: [u8; 20]) -> Result<String, AddressError> {
    if hrp.trim().is_empty() {
        return Err(AddressError::InvalidHrp);
    }
    if !hrp.starts_with('s') {
        return Err(AddressError::InvalidHrpPrefix {
            expected_prefix: 's',
            got: hrp.to_owned(),
        });
    }
    let mut payload = Vec::with_capacity(21);
    payload.push(MULTISIG_ADDRESS_DISCRIMINATOR);
    payload.extend_from_slice(&script_hash20);
    bech32::encode(hrp, payload.to_base32(), Variant::Bech32m).map_err(AddressError::Bech32)
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
    let (key_hash_bytes, kind) = match decoded.len() {
        20 => (&decoded[..], AddressKind::P2pkh),
        21 if decoded[0] == MULTISIG_ADDRESS_DISCRIMINATOR => {
            (&decoded[1..], AddressKind::MultiSig)
        }
        _ => {
            return Err(AddressError::InvalidPayloadLength {
                expected: 20,
                got: decoded.len(),
            });
        }
    };
    let mut key_hash20 = [0u8; 20];
    key_hash20.copy_from_slice(key_hash_bytes);
    Ok(DecodedAddress {
        hrp,
        key_hash20,
        kind,
    })
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
    use bech32::ToBase32;
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
        assert_eq!(decoded.kind, crate::address::AddressKind::P2pkh);
    }

    #[test]
    fn multisig_address_encode_decode_roundtrip_and_distinguishable() {
        let script_hash20 = [0x77u8; 20];
        let addr = crate::address::to_multisig_address("sd", script_hash20).expect("encode");
        let decoded = parse_address(&addr).expect("decode");
        assert_eq!(decoded.hrp, "sd");
        assert_eq!(decoded.key_hash20, script_hash20);
        assert_eq!(decoded.kind, crate::address::AddressKind::MultiSig);

        // A multisig address should NOT decode-equal a P2PKH address
        // with the same 20-byte hash — the discriminator byte enforces
        // that addresses of the two kinds never collide on the wire.
        let p2pkh_addr = bech32::encode("sd", script_hash20.to_base32(), bech32::Variant::Bech32m)
            .expect("encode");
        assert_ne!(addr, p2pkh_addr);
    }

    #[test]
    fn malformed_multisig_payload_is_rejected() {
        // 21-byte payload but wrong discriminator → invalid length error
        // (we don't accept any other 21-byte shape).
        let mut payload = vec![0x00u8; 21]; // 0x00 is not MULTISIG_ADDRESS_DISCRIMINATOR
        payload[1..].copy_from_slice(&[0x55u8; 20]);
        let addr =
            bech32::encode("sd", payload.to_base32(), bech32::Variant::Bech32m).expect("encode");
        let err = parse_address(&addr).expect_err("must reject");
        assert!(matches!(
            err,
            crate::address::AddressError::InvalidPayloadLength { .. }
        ));
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
