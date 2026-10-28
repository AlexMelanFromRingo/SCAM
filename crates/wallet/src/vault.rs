use std::fs;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use scam_core::hash::{ParseHexError, decode_hex_array};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::mnemonic::{MnemonicError, WalletMnemonic, WalletSeedMode};

const WALLET_VAULT_VERSION: u32 = 1;
const KDF_MEM_COST_KIB: u32 = 32 * 1024;
const KDF_TIME_COST: u32 = 2;
const KDF_LANES: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletVaultKdfParams {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncryptedWalletVault {
    pub version: u32,
    pub kdf: WalletVaultKdfParams,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Clone, Debug)]
pub struct DecryptedWalletSecret {
    pub mnemonic: WalletMnemonic,
    pub bip39_passphrase: String,
    pub seed_mode: WalletSeedMode,
}

impl Drop for DecryptedWalletSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bip39_passphrase);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WalletSecretPayload {
    mnemonic: String,
    bip39_passphrase: String,
    #[serde(default)]
    seed_mode: WalletSeedMode,
}

impl Drop for WalletSecretPayload {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.mnemonic);
        zeroize::Zeroize::zeroize(&mut self.bip39_passphrase);
    }
}

pub fn new_encrypted_wallet_vault(
    mnemonic_phrase: &str,
    bip39_passphrase: &str,
    encryption_password: &str,
) -> Result<EncryptedWalletVault, WalletVaultError> {
    new_encrypted_wallet_vault_with_mode(
        mnemonic_phrase,
        bip39_passphrase,
        WalletSeedMode::Bip39,
        encryption_password,
    )
}

pub fn new_encrypted_wallet_vault_with_mode(
    mnemonic_phrase: &str,
    bip39_passphrase: &str,
    seed_mode: WalletSeedMode,
    encryption_password: &str,
) -> Result<EncryptedWalletVault, WalletVaultError> {
    if encryption_password.is_empty() {
        return Err(WalletVaultError::EmptyEncryptionPassword);
    }
    let mnemonic = WalletMnemonic::parse(mnemonic_phrase)?;

    let payload = WalletSecretPayload {
        mnemonic: mnemonic.phrase().to_owned(),
        bip39_passphrase: bip39_passphrase.to_owned(),
        seed_mode,
    };
    let plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(&payload).map_err(WalletVaultError::EncodePayload)?,
    );

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let key = zeroize::Zeroizing::new(derive_encryption_key(
        encryption_password,
        &salt,
        KDF_MEM_COST_KIB,
        KDF_TIME_COST,
        KDF_LANES,
    )?);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| WalletVaultError::EncryptFailed)?;

    Ok(EncryptedWalletVault {
        version: WALLET_VAULT_VERSION,
        kdf: WalletVaultKdfParams {
            algorithm: "argon2id".to_owned(),
            memory_kib: KDF_MEM_COST_KIB,
            iterations: KDF_TIME_COST,
            lanes: KDF_LANES,
        },
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

pub fn decrypt_wallet_vault(
    vault: &EncryptedWalletVault,
    encryption_password: &str,
) -> Result<DecryptedWalletSecret, WalletVaultError> {
    if encryption_password.is_empty() {
        return Err(WalletVaultError::EmptyEncryptionPassword);
    }
    if vault.version != WALLET_VAULT_VERSION {
        return Err(WalletVaultError::UnsupportedVersion {
            expected: WALLET_VAULT_VERSION,
            got: vault.version,
        });
    }
    if vault.kdf.algorithm != "argon2id" {
        return Err(WalletVaultError::UnsupportedKdfAlgorithm {
            got: vault.kdf.algorithm.clone(),
        });
    }

    let salt = decode_hex_array::<16>(&vault.salt_hex).map_err(WalletVaultError::InvalidHex)?;
    let nonce = decode_hex_array::<24>(&vault.nonce_hex).map_err(WalletVaultError::InvalidHex)?;
    let ciphertext = hex::decode(&vault.ciphertext_hex).map_err(WalletVaultError::InvalidHexRaw)?;

    let key = zeroize::Zeroizing::new(derive_encryption_key(
        encryption_password,
        &salt,
        vault.kdf.memory_kib,
        vault.kdf.iterations,
        vault.kdf.lanes,
    )?);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plaintext = zeroize::Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| WalletVaultError::DecryptFailed)?,
    );
    let payload: WalletSecretPayload =
        serde_json::from_slice(&plaintext).map_err(WalletVaultError::DecodePayload)?;
    let mnemonic = WalletMnemonic::parse(&payload.mnemonic)?;
    Ok(DecryptedWalletSecret {
        mnemonic,
        bip39_passphrase: payload.bip39_passphrase.clone(),
        seed_mode: payload.seed_mode,
    })
}

/// Write a new vault file. Refuses to overwrite an existing file (a second
/// `secure-new` used to silently destroy the first wallet). The file is
/// created with owner-only permissions on Unix and fsynced.
pub fn save_wallet_vault(
    path: &Path,
    vault: &EncryptedWalletVault,
) -> Result<(), WalletVaultError> {
    if path.exists() {
        return Err(WalletVaultError::VaultExists {
            path: path.display().to_string(),
        });
    }
    write_vault_file(path, vault, false)
}

/// Atomically replace (or create) a vault file: written to a temp file in
/// the same directory, fsynced, then renamed over the target.
pub fn replace_wallet_vault(
    path: &Path,
    vault: &EncryptedWalletVault,
) -> Result<(), WalletVaultError> {
    write_vault_file(path, vault, true)
}

fn write_vault_file(
    path: &Path,
    vault: &EncryptedWalletVault,
    replace: bool,
) -> Result<(), WalletVaultError> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| WalletVaultError::CreateDir {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let bytes = serde_json::to_vec_pretty(vault).map_err(WalletVaultError::EncodeVault)?;
    let write_err = |source| WalletVaultError::WriteVault {
        path: path.display().to_string(),
        source,
    };
    let target = if replace {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".tmp.{}", std::process::id()));
        path.with_file_name(name)
    } else {
        path.to_path_buf()
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&target).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists && !replace {
            WalletVaultError::VaultExists {
                path: path.display().to_string(),
            }
        } else {
            write_err(source)
        }
    })?;
    file.write_all(&bytes).map_err(write_err)?;
    file.sync_all().map_err(write_err)?;
    drop(file);
    if replace {
        fs::rename(&target, path).map_err(|source| {
            let _ = fs::remove_file(&target);
            write_err(source)
        })?;
    }
    Ok(())
}

pub fn load_wallet_vault(path: &Path) -> Result<EncryptedWalletVault, WalletVaultError> {
    let raw = fs::read(path).map_err(|source| WalletVaultError::ReadVault {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_slice(&raw).map_err(WalletVaultError::DecodeVault)
}

fn derive_encryption_key(
    encryption_password: &str,
    salt: &[u8; 16],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<[u8; 32], WalletVaultError> {
    let params = Params::new(memory_kib, iterations, lanes, Some(32))
        .map_err(WalletVaultError::KdfInvalidParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(encryption_password.as_bytes(), salt, &mut key)
        .map_err(WalletVaultError::KdfFailed)?;
    Ok(key)
}

#[derive(Debug, Error)]
pub enum WalletVaultError {
    #[error(
        "wallet vault already exists at {path}; refusing to overwrite (use --force to replace it)"
    )]
    VaultExists { path: String },
    #[error("encryption password must not be empty")]
    EmptyEncryptionPassword,
    #[error("unsupported wallet vault version: expected {expected}, got {got}")]
    UnsupportedVersion { expected: u32, got: u32 },
    #[error("unsupported wallet kdf algorithm: {got}")]
    UnsupportedKdfAlgorithm { got: String },
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(#[from] MnemonicError),
    #[error("invalid hex payload: {0}")]
    InvalidHex(#[source] ParseHexError),
    #[error("invalid hex payload: {0}")]
    InvalidHexRaw(#[source] hex::FromHexError),
    #[error("kdf params are invalid: {0}")]
    KdfInvalidParams(argon2::Error),
    #[error("kdf failed: {0}")]
    KdfFailed(argon2::Error),
    #[error("wallet payload encoding failed: {0}")]
    EncodePayload(#[source] serde_json::Error),
    #[error("wallet payload decoding failed: {0}")]
    DecodePayload(#[source] serde_json::Error),
    #[error("wallet vault encoding failed: {0}")]
    EncodeVault(#[source] serde_json::Error),
    #[error("wallet vault decoding failed: {0}")]
    DecodeVault(#[source] serde_json::Error),
    #[error("wallet encryption failed")]
    EncryptFailed,
    #[error("wallet decryption failed (wrong password or corrupted payload)")]
    DecryptFailed,
    #[error("cannot create wallet directory {path}: {source}")]
    CreateDir {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot write wallet vault to {path}: {source}")]
    WriteVault {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot read wallet vault from {path}: {source}")]
    ReadVault {
        path: String,
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use std::path::PathBuf;

    use crate::mnemonic::WalletSeedMode;
    use crate::vault::{
        decrypt_wallet_vault, load_wallet_vault, new_encrypted_wallet_vault,
        new_encrypted_wallet_vault_with_mode, replace_wallet_vault, save_wallet_vault,
    };

    /// R3: saving must never silently overwrite an existing vault; replace is
    /// explicit and atomic; files are owner-only on Unix.
    #[test]
    fn save_refuses_overwrite_and_replace_is_explicit() {
        let path = temp_test_file("vault-overwrite");
        let first = new_encrypted_wallet_vault(MNEMONIC, "", "pw-1").expect("vault 1");
        save_wallet_vault(&path, &first).expect("first save");
        let second = new_encrypted_wallet_vault(MNEMONIC, "", "pw-2").expect("vault 2");
        let err = save_wallet_vault(&path, &second).expect_err("overwrite must be refused");
        assert!(matches!(
            err,
            crate::vault::WalletVaultError::VaultExists { .. }
        ));
        // The original is intact and still opens with its password.
        let loaded = load_wallet_vault(&path).expect("load");
        decrypt_wallet_vault(&loaded, "pw-1").expect("original password still works");

        replace_wallet_vault(&path, &second).expect("explicit replace");
        let loaded = load_wallet_vault(&path).expect("load replaced");
        decrypt_wallet_vault(&loaded, "pw-2").expect("new password works");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o077, 0, "vault must not be group/world accessible");
        }
        let _ = std::fs::remove_file(path);
    }

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn temp_test_file(stem: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "scam-{stem}-{}-{ts}-{nonce}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn vault_encrypt_decrypt_roundtrip() {
        let vault =
            new_encrypted_wallet_vault(MNEMONIC, "seed-passphrase", "encrypt-pass").expect("vault");
        let secret = decrypt_wallet_vault(&vault, "encrypt-pass").expect("decrypt");
        assert_eq!(secret.mnemonic.phrase(), MNEMONIC);
        assert_eq!(secret.bip39_passphrase, "seed-passphrase");
        assert_eq!(secret.seed_mode, WalletSeedMode::Bip39);
    }

    #[test]
    fn vault_uses_frozen_kdf_defaults() {
        let vault = new_encrypted_wallet_vault(MNEMONIC, "", "encrypt-pass").expect("vault");
        assert_eq!(vault.kdf.algorithm, "argon2id");
        assert_eq!(vault.kdf.memory_kib, 32 * 1024);
        assert_eq!(vault.kdf.iterations, 2);
        assert_eq!(vault.kdf.lanes, 1);
    }

    #[test]
    fn wrong_password_fails_decrypt() {
        let vault = new_encrypted_wallet_vault(MNEMONIC, "", "good-pass").expect("vault");
        let err = decrypt_wallet_vault(&vault, "bad-pass").expect_err("must fail");
        assert!(matches!(err, crate::vault::WalletVaultError::DecryptFailed));
    }

    #[test]
    fn vault_file_roundtrip() {
        let vault = new_encrypted_wallet_vault(MNEMONIC, "x", "vault-pass").expect("vault");
        let path = temp_test_file("wallet-vault");
        save_wallet_vault(&path, &vault).expect("save");
        let loaded = load_wallet_vault(&path).expect("load");
        let secret = decrypt_wallet_vault(&loaded, "vault-pass").expect("decrypt");
        assert_eq!(secret.mnemonic.phrase(), MNEMONIC);
        assert_eq!(secret.bip39_passphrase, "x");
        assert_eq!(secret.seed_mode, WalletSeedMode::Bip39);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn vault_file_roundtrip_with_scam_blake_seed_mode() {
        let vault = new_encrypted_wallet_vault_with_mode(
            MNEMONIC,
            "x",
            WalletSeedMode::ScamBlake,
            "vault-pass",
        )
        .expect("vault");
        let path = temp_test_file("wallet-vault-blake");
        save_wallet_vault(&path, &vault).expect("save");
        let loaded = load_wallet_vault(&path).expect("load");
        let secret = decrypt_wallet_vault(&loaded, "vault-pass").expect("decrypt");
        assert_eq!(secret.mnemonic.phrase(), MNEMONIC);
        assert_eq!(secret.bip39_passphrase, "x");
        assert_eq!(secret.seed_mode, WalletSeedMode::ScamBlake);
        let _ = std::fs::remove_file(path);
    }
}
