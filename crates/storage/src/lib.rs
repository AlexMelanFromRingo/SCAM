use std::fs;
use std::path::Path;

use redb::{Database, ReadableTable, TableDefinition};
use scam_consensus::{UtxoEntry, UtxoSet};
use scam_core::{Block, BlockHeader, Hash256, OutPoint};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("chain_meta");
const UTXO_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("utxos");
const BLOCK_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks_by_hash");
const HEADER_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers_by_hash");
const BLOCK_INDEX_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("block_index");

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainArchive {
    pub network_id: String,
    pub blocks_by_height: Vec<Block>,
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

pub fn save_snapshot_db(path: &Path, snapshot: &ChainStateSnapshot) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| StorageError::CreateDir {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let tmp_path = temp_db_path(path);
    if tmp_path.exists() {
        fs::remove_file(&tmp_path).map_err(|source| StorageError::Write {
            path: tmp_path.display().to_string(),
            source,
        })?;
    }

    let db = Database::create(&tmp_path).map_err(|e| StorageError::Db(e.to_string()))?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    {
        let mut meta = write_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let tip_height_bytes = snapshot.tip_height.to_le_bytes();
        let block_hashes =
            bincode::serialize(&snapshot.block_hashes_by_height).map_err(StorageError::Encode)?;
        meta.insert("network_id", snapshot.network_id.as_bytes())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        meta.insert("tip_height", tip_height_bytes.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        meta.insert("tip_hash", snapshot.tip_hash.0.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        meta.insert("block_hashes", block_hashes.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
    }
    {
        let mut utxos = write_txn
            .open_table(UTXO_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        for record in &snapshot.utxos {
            let key = bincode::serialize(&record.outpoint).map_err(StorageError::Encode)?;
            let value = bincode::serialize(&record.entry).map_err(StorageError::Encode)?;
            utxos
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    fs::rename(&tmp_path, path).map_err(|source| StorageError::Write {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

pub fn load_snapshot_db(path: &Path) -> Result<ChainStateSnapshot, StorageError> {
    let db = Database::open(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StorageError::Db(e.to_string()))?;

    let (network_id, tip_height, tip_hash, block_hashes_by_height) = {
        let meta = read_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;

        let network_id_raw = meta
            .get("network_id")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("network_id".to_owned()))?;
        let tip_height_raw = meta
            .get("tip_height")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("tip_height".to_owned()))?;
        let tip_hash_raw = meta
            .get("tip_hash")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("tip_hash".to_owned()))?;
        let block_hashes_raw = meta
            .get("block_hashes")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("block_hashes".to_owned()))?;

        let network_id = std::str::from_utf8(network_id_raw.value())
            .map_err(StorageError::InvalidUtf8)?
            .to_owned();

        let tip_height_bytes = tip_height_raw.value();
        if tip_height_bytes.len() != 8 {
            return Err(StorageError::InvalidMetaFormat {
                key: "tip_height".to_owned(),
                details: format!("expected 8 bytes, got {}", tip_height_bytes.len()),
            });
        }
        let mut tip_height_buf = [0u8; 8];
        tip_height_buf.copy_from_slice(tip_height_bytes);
        let tip_height = u64::from_le_bytes(tip_height_buf);

        let tip_hash_bytes = tip_hash_raw.value();
        if tip_hash_bytes.len() != 32 {
            return Err(StorageError::InvalidMetaFormat {
                key: "tip_hash".to_owned(),
                details: format!("expected 32 bytes, got {}", tip_hash_bytes.len()),
            });
        }
        let mut tip_hash_buf = [0u8; 32];
        tip_hash_buf.copy_from_slice(tip_hash_bytes);
        let tip_hash = Hash256(tip_hash_buf);

        let block_hashes_by_height: Vec<Hash256> =
            bincode::deserialize(block_hashes_raw.value()).map_err(StorageError::Decode)?;
        (network_id, tip_height, tip_hash, block_hashes_by_height)
    };

    let utxos_table = read_txn
        .open_table(UTXO_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut utxos = Vec::<UtxoRecord>::new();
    for row in utxos_table
        .iter()
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (key, value) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let outpoint: OutPoint = bincode::deserialize(key.value()).map_err(StorageError::Decode)?;
        let entry: UtxoEntry = bincode::deserialize(value.value()).map_err(StorageError::Decode)?;
        utxos.push(UtxoRecord { outpoint, entry });
    }
    utxos.sort_by(|a, b| {
        a.outpoint
            .txid
            .cmp(&b.outpoint.txid)
            .then(a.outpoint.vout.cmp(&b.outpoint.vout))
    });

    Ok(ChainStateSnapshot {
        network_id,
        tip_height,
        tip_hash,
        block_hashes_by_height,
        utxos,
    })
}

pub fn save_chain_archive_db(path: &Path, archive: &ChainArchive) -> Result<(), StorageError> {
    if archive.blocks_by_height.is_empty() {
        return Err(StorageError::InvalidArchive(
            "blocks_by_height cannot be empty".to_owned(),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| StorageError::CreateDir {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let tmp_path = temp_db_path(path);
    if tmp_path.exists() {
        fs::remove_file(&tmp_path).map_err(|source| StorageError::Write {
            path: tmp_path.display().to_string(),
            source,
        })?;
    }

    let db = Database::create(&tmp_path).map_err(|e| StorageError::Db(e.to_string()))?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    {
        let mut meta = write_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let tip_height = (archive.blocks_by_height.len() as u64).saturating_sub(1);
        meta.insert("network_id", archive.network_id.as_bytes())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        meta.insert("tip_height", tip_height.to_le_bytes().as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let tip_hash = archive
            .blocks_by_height
            .last()
            .expect("non-empty")
            .header
            .block_hash();
        meta.insert("tip_hash", tip_hash.0.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
    }
    {
        let mut blocks_table = write_txn
            .open_table(BLOCK_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let mut headers_table = write_txn
            .open_table(HEADER_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let mut index_table = write_txn
            .open_table(BLOCK_INDEX_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;

        for (height, block) in archive.blocks_by_height.iter().enumerate() {
            let hash = block.header.block_hash();
            let block_bytes = bincode::serialize(block).map_err(StorageError::Encode)?;
            let header_bytes = bincode::serialize(&block.header).map_err(StorageError::Encode)?;

            blocks_table
                .insert(hash.0.as_slice(), block_bytes.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
            headers_table
                .insert(hash.0.as_slice(), header_bytes.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
            index_table
                .insert(height as u64, hash.0.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    fs::rename(&tmp_path, path).map_err(|source| StorageError::Write {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

pub fn load_chain_archive_db(path: &Path) -> Result<ChainArchive, StorageError> {
    let db = Database::open(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let network_id = {
        let meta = read_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let network_id_raw = meta
            .get("network_id")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("network_id".to_owned()))?;
        std::str::from_utf8(network_id_raw.value())
            .map_err(StorageError::InvalidUtf8)?
            .to_owned()
    };

    let index_table = read_txn
        .open_table(BLOCK_INDEX_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let blocks_table = read_txn
        .open_table(BLOCK_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let headers_table = read_txn
        .open_table(HEADER_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;

    let mut blocks_by_height = Vec::<Block>::new();
    for row in index_table
        .iter()
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (height_key, hash_bytes) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let expected_height = blocks_by_height.len() as u64;
        if height_key.value() != expected_height {
            return Err(StorageError::InvalidArchive(format!(
                "block index gap: expected height {}, got {}",
                expected_height,
                height_key.value()
            )));
        }

        let hash = bytes_to_hash(hash_bytes.value(), "block_index hash")?;
        let block_raw = blocks_table
            .get(hash.0.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingArchiveRecord {
                table: "blocks_by_hash",
                key: hash.to_string(),
            })?;
        let header_raw = headers_table
            .get(hash.0.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingArchiveRecord {
                table: "headers_by_hash",
                key: hash.to_string(),
            })?;

        let block: Block = bincode::deserialize(block_raw.value()).map_err(StorageError::Decode)?;
        let header: BlockHeader =
            bincode::deserialize(header_raw.value()).map_err(StorageError::Decode)?;
        if block.header != header {
            return Err(StorageError::InvalidArchive(format!(
                "header mismatch for block {}",
                hash
            )));
        }
        blocks_by_height.push(block);
    }
    if blocks_by_height.is_empty() {
        return Err(StorageError::InvalidArchive(
            "archive contains no indexed blocks".to_owned(),
        ));
    }
    Ok(ChainArchive {
        network_id,
        blocks_by_height,
    })
}

fn bytes_to_hash(raw: &[u8], context: &str) -> Result<Hash256, StorageError> {
    if raw.len() != 32 {
        return Err(StorageError::InvalidMetaFormat {
            key: context.to_owned(),
            details: format!("expected 32 bytes, got {}", raw.len()),
        });
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(raw);
    Ok(Hash256(buf))
}

fn temp_db_path(path: &Path) -> std::path::PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.tmp"))
        .unwrap_or_else(|| "chain.tmp".to_owned());
    path.with_file_name(file_name)
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
    #[error("redb error: {0}")]
    Db(String),
    #[error("missing required db metadata key: {0}")]
    MissingMeta(String),
    #[error("invalid metadata format for key {key}: {details}")]
    InvalidMetaFormat { key: String, details: String },
    #[error("invalid utf8 in metadata: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("missing archive record in {table} for key {key}")]
    MissingArchiveRecord { table: &'static str, key: String },
    #[error("invalid chain archive: {0}")]
    InvalidArchive(String),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use scam_consensus::UtxoSet;
    use scam_core::{Block, BlockHeader, Hash256, OutPoint, Target};

    use crate::{
        ChainArchive, ChainStateSnapshot, UtxoRecord, load_chain_archive_db, load_snapshot,
        load_snapshot_db, save_chain_archive_db, save_snapshot, save_snapshot_db,
    };

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
    fn snapshot_db_roundtrip() {
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint {
                txid: Hash256::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000002",
                )
                .expect("hash"),
                vout: 1,
            },
            scam_consensus::UtxoEntry {
                value: 100,
                key_hash20: [2u8; 20],
                created_height: 7,
                is_coinbase: false,
            },
        );

        let snapshot = ChainStateSnapshot::from_utxo_set(
            "devnet".to_owned(),
            7,
            Hash256::from_hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                .expect("hash"),
            vec![
                Hash256::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .expect("hash"),
                Hash256::from_hex(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .expect("hash"),
            ],
            &utxos,
        );

        let path = PathBuf::from("target/test-snapshot.redb");
        save_snapshot_db(&path, &snapshot).expect("save db");
        let loaded = load_snapshot_db(&path).expect("load db");
        assert_eq!(loaded.network_id, "devnet");
        assert_eq!(loaded.tip_height, 7);
        assert_eq!(loaded.tip_hash, snapshot.tip_hash);
        assert_eq!(loaded.block_hashes_by_height.len(), 2);
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

    #[test]
    fn chain_archive_db_roundtrip() {
        let genesis = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .expect("hash"),
                timestamp: 1_770_763_200,
                target: Target::MAX,
                nonce: 1,
            },
            transactions: vec![],
        };
        let block1 = Block {
            header: BlockHeader {
                version: 1,
                prev_block: genesis.header.block_hash(),
                merkle_root: Hash256::from_hex(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .expect("hash"),
                timestamp: 1_770_763_320,
                target: Target::MAX,
                nonce: 2,
            },
            transactions: vec![],
        };
        let archive = ChainArchive {
            network_id: "devnet".to_owned(),
            blocks_by_height: vec![genesis.clone(), block1.clone()],
        };

        let path = PathBuf::from("target/test-chain-archive.redb");
        save_chain_archive_db(&path, &archive).expect("save archive");
        let loaded = load_chain_archive_db(&path).expect("load archive");
        assert_eq!(loaded.network_id, "devnet");
        assert_eq!(loaded.blocks_by_height.len(), 2);
        assert_eq!(loaded.blocks_by_height[0], genesis);
        assert_eq!(loaded.blocks_by_height[1], block1);
        let _ = std::fs::remove_file(path);
    }
}
