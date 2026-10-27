#![cfg_attr(not(test), deny(clippy::unwrap_used))]
pub mod address;
pub mod mnemonic;
pub mod psbt;
pub mod qr;
pub mod rescan;
pub mod signer;
pub mod vault;

pub use address::{
    AddressError, AddressKind, DecodedAddress, MULTISIG_ADDRESS_DISCRIMINATOR,
    key_hash20_from_compressed_pubkey, parse_address, to_address, to_multisig_address,
};
pub use mnemonic::{MnemonicError, WalletMnemonic, WalletSeedMode, new_mnemonic};
pub use psbt::{
    InspectStatus, PARTIAL_MULTISIG_TX_VERSION, PartialMultisigError, PartialMultisigInput,
    PartialMultisigTx,
};
pub use qr::{QrError, qr_for_payment_uri, qr_for_text};
pub use rescan::{
    OwnedUtxo, RescanBalance, RescanError, RescanReport, WatchedKey, derive_watched_keys,
    rescan_blocks,
};
pub use signer::{
    BIP44_PURPOSE, DeriveKeyError, EXTERNAL_CHANGE, SCAM_COIN_TYPE, SchnorrError, WalletKey,
    account_index_from_derivation_path, derivation_path, derivation_path_string, derive_wallet_key,
    derive_wallet_key_from_path, sign_digest, verify_digest,
};
pub use vault::{
    DecryptedWalletSecret, EncryptedWalletVault, WalletVaultError, decrypt_wallet_vault,
    load_wallet_vault, new_encrypted_wallet_vault, new_encrypted_wallet_vault_with_mode,
    replace_wallet_vault, save_wallet_vault,
};
