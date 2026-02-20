use bip39::{Language, Mnemonic};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct WalletMnemonic {
    phrase: String,
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
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &self.phrase)
            .expect("stored phrase must always be valid mnemonic");
        mnemonic.to_seed(passphrase)
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
}

impl From<bip39::Error> for MnemonicError {
    fn from(value: bip39::Error) -> Self {
        Self::GenerateFailed(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::mnemonic::{WalletMnemonic, new_mnemonic};

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
}
