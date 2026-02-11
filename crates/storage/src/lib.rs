use std::fs;
use std::path::Path;

use scam_consensus::{UtxoEntry, UtxoSet};
use scam_core::{Hash256, OutPoint};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainStateSnapshot {
    pub network_id: String,
    pub tip_height: u64,
    pub tip_hash: Hash256,
    pub block_hashes_by_height: Vec<Hash256>,
    pub utxos: Vec<UtxoRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoRecord {
    pub outpoint: OutPoint,
    pub entry: UtxoEntry,
}

impl ChainStateSnapshot {
    pub fn from_utxo_set(
        network_id: String,
        tip_height: u64,
        tip_hash: Hash256,
        block_hashes_by_height: Vec<Hash256>,
        utxos: &UtxoSet,
    ) -> Self {
        let mut utxo_records = utxos
            .iter()
            .map(|(outpoint, entry)| UtxoRecord {
                outpoint: outpoint.clone(),
                entry: entry.clone(),
            })
            .collect::<Vec<_>>();
        utxo_records.sort_by(|a, b| {
            a.outpoint
                .txid
                .cmp(&b.outpoint.txid)
                .then(a.outpoint.vout.cmp(&b.outpoint.vout))
        });

        Self {
            network_id,
            tip_height,
            tip_hash,
            block_hashes_by_height,
            utxos: utxo_records,
        }
    }

    pub fn to_utxo_set(&self) -> UtxoSet {
        let mut set = UtxoSet::new();
        for record in &self.utxos {
            set.insert(record.outpoint.clone(), record.entry.clone());
        }
        set
    }
}

pub fn save_snapshot(path: &Path, snapshot: &ChainStateSnapshot) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| StorageError::CreateDir {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let bytes = bincode::serialize(snapshot).map_err(StorageError::Encode)?;
    fs::write(path, bytes).map_err(|source| StorageError::Write {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

pub fn load_snapshot(path: &Path) -> Result<ChainStateSnapshot, StorageError> {
    let raw = fs::read(path).map_err(|source| StorageError::Read {
        path: path.display().to_string(),
        source,
    })?;
    bincode::deserialize(&raw).map_err(StorageError::Decode)
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("cannot create directory {path}: {source}")]
    CreateDir {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot write snapshot to {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot read snapshot from {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("snapshot encode failed: {0}")]
    Encode(#[source] bincode::Error),
    #[error("snapshot decode failed: {0}")]
    Decode(#[source] bincode::Error),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use scam_consensus::UtxoSet;
    use scam_core::{Hash256, OutPoint};

    use crate::{ChainStateSnapshot, UtxoRecord, load_snapshot, save_snapshot};

    #[test]
    fn snapshot_roundtrip() {
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint {
                txid: Hash256::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )
                .expect("hash"),
                vout: 0,
            },
            scam_consensus::UtxoEntry {
                value: 50,
                key_hash20: [1u8; 20],
                created_height: 0,
                is_coinbase: true,
            },
        );

        let snapshot = ChainStateSnapshot::from_utxo_set(
            "devnet".to_owned(),
            0,
            Hash256::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("hash"),
            vec![
                Hash256::from_hex(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                )
                .expect("hash"),
            ],
            &utxos,
        );

        let path = PathBuf::from("target/test-snapshot.bin");
        save_snapshot(&path, &snapshot).expect("save");
        let loaded = load_snapshot(&path).expect("load");
        assert_eq!(loaded.network_id, "devnet");
        assert_eq!(loaded.tip_height, 0);
        assert_eq!(loaded.utxos.len(), 1);
        assert_eq!(loaded.to_utxo_set().len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn record_type_is_constructible() {
        let _record = UtxoRecord {
            outpoint: OutPoint::coinbase(),
            entry: scam_consensus::UtxoEntry {
                value: 1,
                key_hash20: [0u8; 20],
                created_height: 0,
                is_coinbase: false,
            },
        };
    }
}
