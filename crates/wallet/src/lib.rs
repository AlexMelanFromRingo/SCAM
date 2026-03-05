pub mod address;
pub mod mnemonic;
pub mod qr;
pub mod rescan;
pub mod signer;
pub mod vault;

pub use address::{
    AddressError, DecodedAddress, key_hash20_from_compressed_pubkey, parse_address, to_address,
};
pub use mnemonic::{MnemonicError, WalletMnemonic, WalletSeedMode, new_mnemonic};
pub use qr::{QrError, qr_for_payment_uri, qr_for_text};
pub use rescan::{
    OwnedUtxo, RescanBalance, RescanError, RescanReport, WatchedKey, derive_watched_keys,
    rescan_blocks,
};
pub use signer::{
    BIP44_PURPOSE, DeriveKeyError, EXTERNAL_CHANGE, SCAM_COIN_TYPE, SchnorrError, WalletKey,
    derivation_path, derivation_path_string, derive_wallet_key, sign_digest, verify_digest,
};
pub use vault::{
    DecryptedWalletSecret, EncryptedWalletVault, WalletVaultError, decrypt_wallet_vault,
    load_wallet_vault, new_encrypted_wallet_vault, new_encrypted_wallet_vault_with_mode,
    save_wallet_vault,
};
