use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use thiserror::Error;

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

pub fn derive_wallet_key(
    seed: &[u8],
    account: u32,
    index: u32,
) -> Result<WalletKey, DeriveKeyError> {
    if seed.is_empty() {
        return Err(DeriveKeyError::EmptySeed);
    }

    let secp = Secp256k1::new();
    for counter in 0u32..2048 {
        let mut material = Vec::with_capacity(seed.len() + 32);
        material.extend_from_slice(seed);
        material.extend_from_slice(b"SCAM-wallet-v1");
        material.extend_from_slice(&account.to_le_bytes());
        material.extend_from_slice(&index.to_le_bytes());
        material.extend_from_slice(&counter.to_le_bytes());

        let digest = blake3::hash(&material);
        if let Ok(secret_key) = SecretKey::from_slice(digest.as_bytes()) {
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            return Ok(WalletKey {
                secret_key,
                pubkey_compressed: public_key.serialize(),
            });
        }
    }

    Err(DeriveKeyError::NoValidSecretKey)
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
    #[error("could not derive valid secp256k1 secret key")]
    NoValidSecretKey,
}

#[derive(Debug, Error)]
pub enum SchnorrError {
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[source] secp256k1::Error),
}

#[cfg(test)]
mod tests {
    use crate::signer::{derive_wallet_key, sign_digest, verify_digest};

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
}
