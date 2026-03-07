use std::str::FromStr;

use bitcoin::Network;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use thiserror::Error;

pub const BIP44_PURPOSE: u32 = 44;
pub const SCAM_COIN_TYPE: u32 = 1337;
pub const EXTERNAL_CHANGE: u32 = 0;

#[derive(Clone)]
pub struct WalletKey {
    secret_key: SecretKey,
    pubkey_compressed: [u8; 33],
}

impl WalletKey {
    pub fn pubkey_compressed(&self) -> [u8; 33] {
        self.pubkey_compressed
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret_key.secret_bytes()
    }
}

pub fn derivation_path(account: u32, index: u32) -> Result<DerivationPath, DeriveKeyError> {
    let purpose =
        ChildNumber::from_hardened_idx(BIP44_PURPOSE).map_err(DeriveKeyError::Bip32Path)?;
    let coin_type =
        ChildNumber::from_hardened_idx(SCAM_COIN_TYPE).map_err(DeriveKeyError::Bip32Path)?;
    let account = ChildNumber::from_hardened_idx(account).map_err(DeriveKeyError::Bip32Path)?;
    let change =
        ChildNumber::from_normal_idx(EXTERNAL_CHANGE).map_err(DeriveKeyError::Bip32Path)?;
    let index = ChildNumber::from_normal_idx(index).map_err(DeriveKeyError::Bip32Path)?;
    Ok(DerivationPath::from(vec![
        purpose, coin_type, account, change, index,
    ]))
}

pub fn derivation_path_string(account: u32, index: u32) -> Result<String, DeriveKeyError> {
    Ok(format!("m/{}", derivation_path(account, index)?))
}

pub fn account_index_from_derivation_path(path: &str) -> Result<(u32, u32), DeriveKeyError> {
    let parsed = path.trim();
    if parsed.is_empty() {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    }

    let mut parts = parsed.split('/');
    if parts.next() != Some("m") {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    }
    let Some(purpose_raw) = parts.next() else {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    };
    let Some(coin_type_raw) = parts.next() else {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    };
    let Some(account_raw) = parts.next() else {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    };
    let Some(change_raw) = parts.next() else {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    };
    let Some(index_raw) = parts.next() else {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    };
    if parts.next().is_some() {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    }

    let purpose = parse_hardened_path_component(purpose_raw, path)?;
    if purpose != BIP44_PURPOSE {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    }

    let coin_type = parse_hardened_path_component(coin_type_raw, path)?;
    if coin_type != SCAM_COIN_TYPE {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    }

    let account = parse_hardened_path_component(account_raw, path)?;
    let change = parse_normal_path_component(change_raw, path)?;
    if change != EXTERNAL_CHANGE {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    }

    let index = parse_normal_path_component(index_raw, path)?;
    let expected = derivation_path_string(account, index)?;
    if expected != parsed {
        return Err(DeriveKeyError::InvalidDerivationPath(path.to_owned()));
    }
    Ok((account, index))
}

pub fn derive_wallet_key_from_path(
    seed: &[u8],
    path: &str,
) -> Result<(WalletKey, u32, u32), DeriveKeyError> {
    let (account, index) = account_index_from_derivation_path(path)?;
    let key = derive_wallet_key(seed, account, index)?;
    Ok((key, account, index))
}

fn parse_hardened_path_component(component: &str, full_path: &str) -> Result<u32, DeriveKeyError> {
    let Some(raw_value) = component.strip_suffix('\'') else {
        return Err(DeriveKeyError::InvalidDerivationPath(full_path.to_owned()));
    };
    u32::from_str(raw_value)
        .map_err(|_| DeriveKeyError::InvalidDerivationPath(full_path.to_owned()))
}

fn parse_normal_path_component(component: &str, full_path: &str) -> Result<u32, DeriveKeyError> {
    if component.ends_with('\'') {
        return Err(DeriveKeyError::InvalidDerivationPath(full_path.to_owned()));
    }
    u32::from_str(component)
        .map_err(|_| DeriveKeyError::InvalidDerivationPath(full_path.to_owned()))
}

pub fn derive_wallet_key(
    seed: &[u8],
    account: u32,
    index: u32,
) -> Result<WalletKey, DeriveKeyError> {
    if seed.is_empty() {
        return Err(DeriveKeyError::EmptySeed);
    }

    let secp_bip32 = bitcoin::secp256k1::Secp256k1::new();
    let master = Xpriv::new_master(Network::Bitcoin, seed).map_err(DeriveKeyError::Bip32)?;
    let path = derivation_path(account, index)?;
    let child = master
        .derive_priv(&secp_bip32, &path)
        .map_err(DeriveKeyError::Bip32)?;

    let secret_key = SecretKey::from_slice(&child.private_key.secret_bytes())
        .map_err(DeriveKeyError::Secp256k1)?;
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(WalletKey {
        secret_key,
        pubkey_compressed: public_key.serialize(),
    })
}

pub fn sign_digest(wallet_key: &WalletKey, digest32: [u8; 32]) -> Result<[u8; 64], SchnorrError> {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(&digest32).map_err(SchnorrError::Secp256k1)?;
    let keypair = Keypair::from_secret_key(&secp, &wallet_key.secret_key);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    let mut out = [0u8; 64];
    out.copy_from_slice(signature.as_ref());
    Ok(out)
}

pub fn verify_digest(
    digest32: [u8; 32],
    signature64: [u8; 64],
    pubkey_compressed: [u8; 33],
) -> Result<bool, SchnorrError> {
    let secp = Secp256k1::verification_only();
    let message = Message::from_digest_slice(&digest32).map_err(SchnorrError::Secp256k1)?;
    let signature = Signature::from_slice(&signature64).map_err(SchnorrError::Secp256k1)?;
    let parsed = PublicKey::from_slice(&pubkey_compressed).map_err(SchnorrError::Secp256k1)?;
    let (xonly, _) = parsed.x_only_public_key();
    Ok(secp.verify_schnorr(&signature, &message, &xonly).is_ok())
}

#[derive(Debug, Error)]
pub enum DeriveKeyError {
    #[error("seed must not be empty")]
    EmptySeed,
    #[error("invalid derivation path '{0}' (expected m/44'/1337'/<account>'/0/<index>)")]
    InvalidDerivationPath(String),
    #[error("bip32 derivation failed: {0}")]
    Bip32(#[source] bitcoin::bip32::Error),
    #[error("invalid bip32 path component: {0}")]
    Bip32Path(#[source] bitcoin::bip32::Error),
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[source] secp256k1::Error),
}

#[derive(Debug, Error)]
pub enum SchnorrError {
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[source] secp256k1::Error),
}

#[cfg(test)]
mod tests {
    use crate::signer::{
        account_index_from_derivation_path, derivation_path_string, derive_wallet_key,
        derive_wallet_key_from_path, sign_digest, verify_digest,
    };

    #[test]
    fn schnorr_sign_verify_roundtrip() {
        let seed = [11u8; 64];
        let key = derive_wallet_key(&seed, 0, 0).expect("key derivation");
        let digest = *blake3::hash(b"tx digest").as_bytes();
        let signature = sign_digest(&key, digest).expect("signature");
        let ok =
            verify_digest(digest, signature, key.pubkey_compressed()).expect("verification call");
        assert!(ok);
    }

    #[test]
    fn different_digest_fails_verification() {
        let seed = [22u8; 64];
        let key = derive_wallet_key(&seed, 0, 0).expect("key derivation");
        let digest_a = *blake3::hash(b"digest-a").as_bytes();
        let digest_b = *blake3::hash(b"digest-b").as_bytes();
        let signature = sign_digest(&key, digest_a).expect("signature");
        let ok =
            verify_digest(digest_b, signature, key.pubkey_compressed()).expect("verification call");
        assert!(!ok);
    }

    #[test]
    fn derivation_path_is_frozen() {
        let path = derivation_path_string(2, 7).expect("path");
        assert_eq!(path, "m/44'/1337'/2'/0/7");
    }

    #[test]
    fn derivation_changes_with_index() {
        let seed = [33u8; 64];
        let key_a = derive_wallet_key(&seed, 0, 0).expect("key a");
        let key_b = derive_wallet_key(&seed, 0, 1).expect("key b");
        assert_ne!(key_a.pubkey_compressed(), key_b.pubkey_compressed());
    }

    #[test]
    fn secret_key_bytes_are_nonzero_and_vary_by_index() {
        let seed = [44u8; 64];
        let key_a = derive_wallet_key(&seed, 0, 0).expect("key a");
        let key_b = derive_wallet_key(&seed, 0, 1).expect("key b");

        let sk_a = key_a.secret_key_bytes();
        let sk_b = key_b.secret_key_bytes();
        assert_ne!(sk_a, [0u8; 32]);
        assert_ne!(sk_a, [1u8; 32]);
        assert_ne!(sk_b, [0u8; 32]);
        assert_ne!(sk_b, [1u8; 32]);
        assert_ne!(sk_a, sk_b);
    }

    #[test]
    fn parse_derivation_path_extracts_account_and_index() {
        let (account, index) =
            account_index_from_derivation_path("m/44'/1337'/12'/0/34").expect("path");
        assert_eq!(account, 12);
        assert_eq!(index, 34);
    }

    #[test]
    fn parse_derivation_path_rejects_wrong_purpose_coin_type_or_shape() {
        assert!(account_index_from_derivation_path("m/84'/1337'/0'/0/0").is_err());
        assert!(account_index_from_derivation_path("m/44'/0'/0'/0/0").is_err());
        assert!(account_index_from_derivation_path("m/44'/1337'/0'/1/0").is_err());
        assert!(account_index_from_derivation_path("44'/1337'/0'/0/0").is_err());
    }

    #[test]
    fn derive_wallet_key_from_path_matches_account_index_derivation() {
        let seed = [55u8; 64];
        let (by_path, account, index) =
            derive_wallet_key_from_path(&seed, "m/44'/1337'/2'/0/7").expect("derive by path");
        let by_components =
            derive_wallet_key(&seed, account, index).expect("derive by account/index");
        assert_eq!(account, 2);
        assert_eq!(index, 7);
        assert_eq!(
            by_path.pubkey_compressed(),
            by_components.pubkey_compressed()
        );
    }
}
