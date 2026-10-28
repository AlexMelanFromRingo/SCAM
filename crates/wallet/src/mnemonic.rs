use std::str::FromStr;

use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum WalletSeedMode {
    #[default]
    Bip39,
    ScamBlake,
}

impl WalletSeedMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bip39 => "bip39",
            Self::ScamBlake => "scam-blake",
        }
    }
}

impl FromStr for WalletSeedMode {
    type Err = MnemonicError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "bip39" | "sha512" => Ok(Self::Bip39),
            "scam-blake" | "scam_blake" | "blake3" | "blake" => Ok(Self::ScamBlake),
            other => Err(MnemonicError::InvalidSeedMode(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WalletMnemonic {
    phrase: String,
}

impl Drop for WalletMnemonic {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.phrase);
    }
}

impl WalletMnemonic {
    pub fn parse(phrase: &str) -> Result<Self, MnemonicError> {
        let normalized = phrase.trim();
        if normalized.is_empty() {
            return Err(MnemonicError::EmptyPhrase);
        }

        let parsed = Mnemonic::parse_in_normalized(Language::English, normalized)
            .map_err(MnemonicError::InvalidPhrase)?;
        Ok(Self {
            phrase: parsed.to_string(),
        })
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        self.to_seed_with_mode(passphrase, WalletSeedMode::Bip39)
    }

    pub fn to_seed_with_mode(&self, passphrase: &str, mode: WalletSeedMode) -> [u8; 64] {
        match mode {
            WalletSeedMode::Bip39 => self.to_seed_bip39(passphrase),
            WalletSeedMode::ScamBlake => self.to_seed_scam_blake(passphrase),
        }
    }

    fn to_seed_bip39(&self, passphrase: &str) -> [u8; 64] {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &self.phrase)
            .expect("stored phrase must always be valid mnemonic");
        mnemonic.to_seed(passphrase)
    }

    fn to_seed_scam_blake(&self, passphrase: &str) -> [u8; 64] {
        // SCAM-native deterministic KDF for optional non-BIP39 wallet derivation.
        let mut hasher = blake3::Hasher::new_derive_key("SCAM wallet seed v1");
        hasher.update(self.phrase.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(passphrase.as_bytes());
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);
        out
    }
}

pub fn new_mnemonic(words: usize) -> Result<WalletMnemonic, MnemonicError> {
    let mnemonic = Mnemonic::generate_in(Language::English, words).map_err(MnemonicError::from)?;
    Ok(WalletMnemonic {
        phrase: mnemonic.to_string(),
    })
}

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("mnemonic phrase is empty")]
    EmptyPhrase,
    #[error("invalid mnemonic phrase: {0}")]
    InvalidPhrase(#[source] bip39::Error),
    #[error("cannot generate mnemonic: {0}")]
    GenerateFailed(#[source] bip39::Error),
    #[error("invalid seed mode: {0} (expected: bip39 or scam-blake)")]
    InvalidSeedMode(String),
}

impl From<bip39::Error> for MnemonicError {
    fn from(value: bip39::Error) -> Self {
        Self::GenerateFailed(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::mnemonic::{WalletMnemonic, WalletSeedMode, new_mnemonic};

    #[test]
    fn mnemonic_roundtrip() {
        let generated = new_mnemonic(12).expect("mnemonic generation should work");
        let parsed = WalletMnemonic::parse(generated.phrase()).expect("parse should work");
        assert_eq!(generated.phrase(), parsed.phrase());
    }

    #[test]
    fn seed_is_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = WalletMnemonic::parse(phrase).expect("known mnemonic should parse");
        let seed_a = mnemonic.to_seed("passphrase");
        let seed_b = mnemonic.to_seed("passphrase");
        assert_eq!(seed_a, seed_b);
    }

    #[test]
    fn scam_blake_seed_is_deterministic_and_differs_from_bip39() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = WalletMnemonic::parse(phrase).expect("known mnemonic should parse");
        let blake_a = mnemonic.to_seed_with_mode("passphrase", WalletSeedMode::ScamBlake);
        let blake_b = mnemonic.to_seed_with_mode("passphrase", WalletSeedMode::ScamBlake);
        let bip39 = mnemonic.to_seed_with_mode("passphrase", WalletSeedMode::Bip39);
        assert_eq!(blake_a, blake_b);
        assert_ne!(blake_a, bip39);
    }

    #[test]
    fn seed_mode_parser_accepts_aliases() {
        assert_eq!(
            "bip39".parse::<WalletSeedMode>().expect("mode"),
            WalletSeedMode::Bip39
        );
        assert_eq!(
            "blake3".parse::<WalletSeedMode>().expect("mode"),
            WalletSeedMode::ScamBlake
        );
        assert!("unknown".parse::<WalletSeedMode>().is_err());
    }

    #[test]
    fn seed_mode_as_str_is_stable() {
        assert_eq!(WalletSeedMode::Bip39.as_str(), "bip39");
        assert_eq!(WalletSeedMode::ScamBlake.as_str(), "scam-blake");
    }

    #[test]
    fn seed_matches_known_bip39_vector() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = WalletMnemonic::parse(phrase).expect("known mnemonic should parse");
        let seed = mnemonic.to_seed("TREZOR");
        let expected_hex = concat!(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553",
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        assert_eq!(hex::encode(seed), expected_hex);
    }

    #[test]
    fn scam_blake_seed_is_not_trivial_and_changes_with_passphrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = WalletMnemonic::parse(phrase).expect("known mnemonic should parse");
        let seed_a = mnemonic.to_seed_with_mode("passphrase-a", WalletSeedMode::ScamBlake);
        let seed_b = mnemonic.to_seed_with_mode("passphrase-b", WalletSeedMode::ScamBlake);
        assert_ne!(seed_a, seed_b);
        assert!(
            seed_a.iter().any(|b| *b != 0),
            "scam-blake seed must not be all zeros"
        );
        assert!(
            seed_a.iter().any(|b| *b != 1),
            "scam-blake seed must not be all ones"
        );
    }
}
