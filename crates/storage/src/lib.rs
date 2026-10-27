#![cfg_attr(not(test), deny(clippy::unwrap_used))]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use redb::{Database, ReadableTable, TableDefinition};
use scam_consensus::{UtxoEntry, UtxoSet};
use scam_core::{Block, BlockHeader, Hash256, OutPoint, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("chain_meta");
/// Metadata key holding a store's on-disk format version (u32 LE).
const SCHEMA_VERSION_KEY: &str = "schema_version";
/// Format of the chain archive, chain snapshot, mempool and peer-book
/// stores. An absent key means 1 (the layout is unchanged).
pub const STORE_SCHEMA_VERSION: u32 = 1;
/// Pool ledger format. v2 adds frozen per-round PPLNS credits and settled
/// worker credits; v1 ledgers (no key) cannot be decoded and are refused.
pub const POOL_LEDGER_SCHEMA_VERSION: u32 = 2;
const UTXO_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("utxos");
const BLOCK_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks_by_hash");
const HEADER_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers_by_hash");
const BLOCK_INDEX_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("block_index");
const PEER_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("peers");
const MEMPOOL_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mempool_by_txid");
const POOL_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("pool_meta");
const POOL_WORKER_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("pool_workers");
const POOL_SHARE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("pool_shares");
const POOL_ROUND_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("pool_rounds");
const POOL_PAYOUT_PENDING_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("pool_payout_pending");
const POOL_PAYOUT_COMPLETED_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("pool_payout_completed");

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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PeerAddressBook {
    pub network_id: String,
    pub peers: Vec<PeerAddressRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PeerAddressRecord {
    pub address: String,
    pub last_seen_unix_sec: u64,
    pub ban_score: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MempoolSnapshot {
    pub network_id: String,
    pub entries: Vec<MempoolTxRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MempoolTxRecord {
    pub txid: Hash256,
    pub tx: Transaction,
    pub fee: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct MempoolStoredValue {
    tx: Transaction,
    fee: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PoolShareRecord {
    pub share_key: String,
    pub worker: String,
    pub timestamp_unix_sec: u64,
    pub channel_id: u32,
    pub job_id: u32,
    pub nonce: u64,
    pub ntime: u64,
    pub expected_hashes: f64,
    pub accepted: bool,
    pub is_block: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PoolRoundRecord {
    pub round_id: u64,
    pub start_height: u64,
    pub start_tip_hash: Hash256,
    pub start_unix_sec: u64,
    pub end_height: Option<u64>,
    pub end_tip_hash: Option<Hash256>,
    pub end_unix_sec: Option<u64>,
    pub closed_by_worker: Option<String>,
    pub found_block_hash: Option<Hash256>,
    pub found_block_reward_atomic: u128,
    pub orphaned: bool,
    /// PPLNS split frozen when the round closed. Recomputing it later from
    /// the (capped) share history shrank old rounds' rewards and stopped
    /// payouts to workers already paid.
    pub pplns_credits: Vec<PoolRoundCredit>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PoolRoundCredit {
    pub worker: String,
    pub amount_atomic: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PoolWorkerAccrualRecord {
    pub worker: String,
    pub accepted_total: u64,
    pub rejected_total: u64,
    pub blocks_found_total: u64,
    pub expected_hashes_accumulated: f64,
    pub pplns_accrual_atomic: u128,
    /// PPLNS credits of rounds that have left the round-retention window.
    pub pplns_settled_atomic: u128,
    pub pps_accrual_atomic: u128,
    pub paid_total_atomic: u128,
    pub last_share_unix_sec: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PoolPayoutRecord {
    pub payout_id: String,
    pub worker: String,
    pub amount_atomic: u128,
    pub created_unix_sec: u64,
    pub submitted_txid_hex: Option<String>,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PoolLedgerSnapshot {
    pub network_id: String,
    pub current_round_id: u64,
    pub shares: Vec<PoolShareRecord>,
    pub rounds: Vec<PoolRoundRecord>,
    pub workers: Vec<PoolWorkerAccrualRecord>,
    pub pending_payouts: Vec<PoolPayoutRecord>,
    pub completed_payouts: Vec<PoolPayoutRecord>,
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
        write_schema_version(&mut meta, STORE_SCHEMA_VERSION)?;
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
    atomic_replace_file(&tmp_path, path)?;
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
        check_schema_version(&meta, "chain snapshot", STORE_SCHEMA_VERSION, Some(1))?;

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
        write_schema_version(&mut meta, STORE_SCHEMA_VERSION)?;
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
    atomic_replace_file(&tmp_path, path)?;
    Ok(())
}

fn write_schema_version(
    meta: &mut redb::Table<&str, &[u8]>,
    version: u32,
) -> Result<(), StorageError> {
    meta.insert(SCHEMA_VERSION_KEY, version.to_le_bytes().as_slice())
        .map_err(|e| StorageError::Db(e.to_string()))?;
    Ok(())
}

/// Check a store's format version. `legacy_version` is what an absent key
/// means (`None`: the key is mandatory).
fn check_schema_version<T: redb::ReadableTable<&'static str, &'static [u8]>>(
    meta: &T,
    store: &'static str,
    expected: u32,
    legacy_version: Option<u32>,
) -> Result<(), StorageError> {
    let found = match meta
        .get(SCHEMA_VERSION_KEY)
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        Some(raw) => {
            let bytes: [u8; 4] =
                raw.value()
                    .try_into()
                    .map_err(|_| StorageError::InvalidMetaFormat {
                        key: SCHEMA_VERSION_KEY.to_owned(),
                        details: "expected 4 bytes".to_owned(),
                    })?;
            Some(u32::from_le_bytes(bytes))
        }
        None => legacy_version,
    };
    if found != Some(expected) {
        return Err(StorageError::UnsupportedSchema {
            store,
            found,
            expected,
        });
    }
    Ok(())
}

/// Tip recorded in a chain archive's metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveTip {
    pub network_id: String,
    pub height: u64,
    pub hash: Hash256,
    /// Big-endian cumulative chain work of the tip; `None` for archives
    /// written before work was recorded.
    pub work_be: Option<Vec<u8>>,
}

/// Result of [`persist_chain_archive_incremental_db`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivePersistOutcome {
    /// First height whose index entry was (re)written; `None` if the archive
    /// already matched.
    pub first_written_height: Option<u64>,
    pub blocks_written: usize,
}

/// Compare two big-endian unsigned integers given as bytes.
fn cmp_be_uint(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let a = &a[a.iter().position(|byte| *byte != 0).unwrap_or(a.len())..];
    let b = &b[b.iter().position(|byte| *byte != 0).unwrap_or(b.len())..];
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn read_archive_tip<T: redb::ReadableTable<&'static str, &'static [u8]>>(
    meta: &T,
) -> Result<Option<ArchiveTip>, StorageError> {
    let (Some(height_raw), Some(hash_raw)) = (
        meta.get("tip_height")
            .map_err(|e| StorageError::Db(e.to_string()))?,
        meta.get("tip_hash")
            .map_err(|e| StorageError::Db(e.to_string()))?,
    ) else {
        return Ok(None);
    };
    let height_bytes: [u8; 8] =
        height_raw
            .value()
            .try_into()
            .map_err(|_| StorageError::InvalidMetaFormat {
                key: "tip_height".to_owned(),
                details: "expected 8 bytes".to_owned(),
            })?;
    let hash = bytes_to_hash(hash_raw.value(), "tip_hash")?;
    let network_id = meta
        .get("network_id")
        .map_err(|e| StorageError::Db(e.to_string()))?
        .map(|raw| std::str::from_utf8(raw.value()).map(str::to_owned))
        .transpose()
        .map_err(StorageError::InvalidUtf8)?
        .unwrap_or_default();
    let work_be = meta
        .get("tip_work")
        .map_err(|e| StorageError::Db(e.to_string()))?
        .map(|raw| raw.value().to_vec());
    Ok(Some(ArchiveTip {
        network_id,
        height: u64::from_le_bytes(height_bytes),
        hash,
        work_be,
    }))
}

/// Read only the tip metadata of a chain archive.
pub fn load_chain_archive_tip_db(path: &Path) -> Result<Option<ArchiveTip>, StorageError> {
    let db = Database::open(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let meta = read_txn
        .open_table(META_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    check_schema_version(&meta, "chain archive", STORE_SCHEMA_VERSION, Some(1))?;
    read_archive_tip(&meta)
}

/// Load the main-chain blocks at heights `>= from_height`, in order.
pub fn load_chain_archive_range_db(
    path: &Path,
    from_height: u64,
) -> Result<(String, Vec<(u64, Block)>), StorageError> {
    let db = Database::open(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let network_id = {
        let meta = read_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        check_schema_version(&meta, "chain archive", STORE_SCHEMA_VERSION, Some(1))?;
        let raw = meta
            .get("network_id")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("network_id".to_owned()))?;
        std::str::from_utf8(raw.value())
            .map_err(StorageError::InvalidUtf8)?
            .to_owned()
    };
    let index_table = read_txn
        .open_table(BLOCK_INDEX_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let blocks_table = read_txn
        .open_table(BLOCK_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut out = Vec::new();
    for row in index_table
        .range(from_height..)
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (height, hash_raw) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let hash = bytes_to_hash(hash_raw.value(), "block_index hash")?;
        let block_raw = blocks_table
            .get(hash.0.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingArchiveRecord {
                table: "blocks_by_hash",
                key: hash.to_string(),
            })?;
        let block: Block = bincode::deserialize(block_raw.value()).map_err(StorageError::Decode)?;
        out.push((height.value(), block));
    }
    Ok((network_id, out))
}

/// Persist the main chain into the archive at `path` incrementally, in one
/// redb write transaction (crash-atomic; no full rewrite, no temp file).
///
/// `main_chain` is the writer's main chain by height and `tip_work_be` its
/// cumulative work. Only blocks above the first height where the archive
/// differs are written; stale index entries above the new tip are removed.
///
/// Several processes share this file. To make a lagging writer unable to
/// roll the chain back, the write is refused with
/// [`StorageError::StaleArchiveWriter`] when the archive's tip is not on the
/// writer's main chain and carries at least as much work (or, for legacy
/// archives without recorded work, is higher).
pub fn persist_chain_archive_incremental_db(
    path: &Path,
    network_id: &str,
    main_chain: &[Hash256],
    tip_work_be: &[u8],
    get_block: &dyn Fn(&Hash256) -> Option<Block>,
) -> Result<ArchivePersistOutcome, StorageError> {
    let Some(new_tip_hash) = main_chain.last().copied() else {
        return Err(StorageError::InvalidArchive(
            "main chain cannot be empty".to_owned(),
        ));
    };
    let new_tip_height = (main_chain.len() - 1) as u64;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| StorageError::CreateDir {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let db = Database::create(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let outcome = {
        let mut meta = write_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        if let Some(existing) = meta
            .get("network_id")
            .map_err(|e| StorageError::Db(e.to_string()))?
        {
            let existing = std::str::from_utf8(existing.value())
                .map_err(StorageError::InvalidUtf8)?
                .to_owned();
            if existing != network_id {
                return Err(StorageError::InvalidArchive(format!(
                    "archive network '{existing}' does not match writer network '{network_id}'"
                )));
            }
        }
        let disk_tip = read_archive_tip(&meta)?;

        let mut index_table = write_txn
            .open_table(BLOCK_INDEX_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let index_hash_at = |table: &redb::Table<u64, &[u8]>, height: u64| {
            table
                .get(height)
                .map_err(|e| StorageError::Db(e.to_string()))?
                .map(|raw| bytes_to_hash(raw.value(), "block_index hash"))
                .transpose()
        };

        // First height at which the archive's index differs from ours.
        let first_diff = match &disk_tip {
            None => 0,
            Some(tip) => {
                let tip_on_our_chain = main_chain.get(tip.height as usize) == Some(&tip.hash);
                if !tip_on_our_chain {
                    let disk_wins = match &tip.work_be {
                        Some(work) => cmp_be_uint(work, tip_work_be).is_ge(),
                        None => tip.height >= new_tip_height,
                    };
                    if disk_wins {
                        return Err(StorageError::StaleArchiveWriter {
                            disk_tip: tip.hash,
                            disk_height: tip.height,
                        });
                    }
                }
                let mut height = tip.height.min(new_tip_height);
                loop {
                    let ours = main_chain.get(height as usize);
                    if index_hash_at(&index_table, height)?.as_ref() == ours {
                        break height + 1;
                    }
                    if height == 0 {
                        break 0;
                    }
                    height -= 1;
                }
            }
        };

        let mut blocks_table = write_txn
            .open_table(BLOCK_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let mut headers_table = write_txn
            .open_table(HEADER_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let mut blocks_written = 0usize;
        for height in first_diff..=new_tip_height {
            let hash = main_chain[height as usize];
            let already_stored = blocks_table
                .get(hash.0.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?
                .is_some();
            if !already_stored {
                let block = get_block(&hash).ok_or_else(|| StorageError::MissingArchiveRecord {
                    table: "writer main chain",
                    key: hash.to_string(),
                })?;
                let block_bytes = bincode::serialize(&block).map_err(StorageError::Encode)?;
                let header_bytes =
                    bincode::serialize(&block.header).map_err(StorageError::Encode)?;
                blocks_table
                    .insert(hash.0.as_slice(), block_bytes.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
                headers_table
                    .insert(hash.0.as_slice(), header_bytes.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
                blocks_written += 1;
            }
            index_table
                .insert(height, hash.0.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
        if let Some(tip) = &disk_tip {
            for height in (new_tip_height + 1)..=tip.height.max(new_tip_height) {
                index_table
                    .remove(height)
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
        }

        meta.insert("network_id", network_id.as_bytes())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        write_schema_version(&mut meta, STORE_SCHEMA_VERSION)?;
        meta.insert("tip_height", new_tip_height.to_le_bytes().as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        meta.insert("tip_hash", new_tip_hash.0.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        meta.insert("tip_work", tip_work_be)
            .map_err(|e| StorageError::Db(e.to_string()))?;

        ArchivePersistOutcome {
            first_written_height: (first_diff <= new_tip_height).then_some(first_diff),
            blocks_written,
        }
    };
    write_txn
        .commit()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    Ok(outcome)
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
        check_schema_version(&meta, "chain archive", STORE_SCHEMA_VERSION, Some(1))?;
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

pub fn load_block_by_hash_db(path: &Path, hash: Hash256) -> Result<Option<Block>, StorageError> {
    let db = Database::open(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let blocks_table = read_txn
        .open_table(BLOCK_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let Some(block_raw) = blocks_table
        .get(hash.0.as_slice())
        .map_err(|e| StorageError::Db(e.to_string()))?
    else {
        return Ok(None);
    };

    let block: Block = bincode::deserialize(block_raw.value()).map_err(StorageError::Decode)?;
    if block.header.block_hash() != hash {
        return Err(StorageError::InvalidArchive(format!(
            "block hash mismatch for key {}",
            hash
        )));
    }
    Ok(Some(block))
}

pub fn save_peer_book_db(path: &Path, peer_book: &PeerAddressBook) -> Result<(), StorageError> {
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

    let mut dedup = std::collections::HashMap::<String, PeerAddressRecord>::new();
    for record in &peer_book.peers {
        if record.address.trim().is_empty() {
            return Err(StorageError::InvalidPeerBook(
                "peer address cannot be empty".to_owned(),
            ));
        }
        dedup.insert(record.address.clone(), record.clone());
    }
    let mut peers = dedup.into_values().collect::<Vec<_>>();
    peers.sort_by(|a, b| a.address.cmp(&b.address));

    let db = Database::create(&tmp_path).map_err(|e| StorageError::Db(e.to_string()))?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    {
        let mut meta = write_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        meta.insert("network_id", peer_book.network_id.as_bytes())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        write_schema_version(&mut meta, STORE_SCHEMA_VERSION)?;
    }
    {
        let mut peer_table = write_txn
            .open_table(PEER_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        for record in peers {
            let value = bincode::serialize(&record).map_err(StorageError::Encode)?;
            peer_table
                .insert(record.address.as_str(), value.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    atomic_replace_file(&tmp_path, path)?;
    Ok(())
}

pub fn load_peer_book_db(path: &Path) -> Result<PeerAddressBook, StorageError> {
    let db = Database::open(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let network_id = {
        let meta = read_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        check_schema_version(&meta, "peer book", STORE_SCHEMA_VERSION, Some(1))?;
        let network_id_raw = meta
            .get("network_id")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("network_id".to_owned()))?;
        std::str::from_utf8(network_id_raw.value())
            .map_err(StorageError::InvalidUtf8)?
            .to_owned()
    };

    let peer_table = read_txn
        .open_table(PEER_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut peers = Vec::<PeerAddressRecord>::new();
    for row in peer_table
        .iter()
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (key, value) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let key_address = key.value().to_owned();
        let record: PeerAddressRecord =
            bincode::deserialize(value.value()).map_err(StorageError::Decode)?;
        if record.address != key_address {
            return Err(StorageError::InvalidPeerBook(format!(
                "peer key mismatch: key={key_address}, record={}",
                record.address
            )));
        }
        peers.push(record);
    }
    peers.sort_by(|a, b| a.address.cmp(&b.address));

    Ok(PeerAddressBook { network_id, peers })
}

pub fn save_mempool_db(path: &Path, snapshot: &MempoolSnapshot) -> Result<(), StorageError> {
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

    let mut dedup = std::collections::HashMap::<Hash256, MempoolTxRecord>::new();
    for entry in &snapshot.entries {
        let computed = entry.tx.txid();
        if computed != entry.txid {
            return Err(StorageError::InvalidMempool(format!(
                "txid mismatch in mempool snapshot: provided={}, computed={}",
                entry.txid, computed
            )));
        }
        dedup.insert(entry.txid, entry.clone());
    }
    let mut entries = dedup.into_values().collect::<Vec<_>>();
    entries.sort_by_key(|e| e.txid);

    let db = Database::create(&tmp_path).map_err(|e| StorageError::Db(e.to_string()))?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    {
        let mut meta = write_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        meta.insert("network_id", snapshot.network_id.as_bytes())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        write_schema_version(&mut meta, STORE_SCHEMA_VERSION)?;
        let count = entries.len() as u64;
        meta.insert("tx_count", count.to_le_bytes().as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
    }
    {
        let mut table = write_txn
            .open_table(MEMPOOL_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        for entry in entries {
            let value = MempoolStoredValue {
                tx: entry.tx,
                fee: entry.fee,
            };
            let value_bytes = bincode::serialize(&value).map_err(StorageError::Encode)?;
            table
                .insert(entry.txid.0.as_slice(), value_bytes.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    atomic_replace_file(&tmp_path, path)?;
    Ok(())
}

pub fn load_mempool_db(path: &Path) -> Result<MempoolSnapshot, StorageError> {
    let db = Database::open(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StorageError::Db(e.to_string()))?;

    let network_id = {
        let meta = read_txn
            .open_table(META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        check_schema_version(&meta, "mempool", STORE_SCHEMA_VERSION, Some(1))?;
        let network_id_raw = meta
            .get("network_id")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("network_id".to_owned()))?;
        std::str::from_utf8(network_id_raw.value())
            .map_err(StorageError::InvalidUtf8)?
            .to_owned()
    };

    let table = read_txn
        .open_table(MEMPOOL_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut entries = Vec::<MempoolTxRecord>::new();
    for row in table.iter().map_err(|e| StorageError::Db(e.to_string()))? {
        let (key, value) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let txid = bytes_to_hash(key.value(), "mempool txid")?;
        let stored: MempoolStoredValue =
            bincode::deserialize(value.value()).map_err(StorageError::Decode)?;
        let computed = stored.tx.txid();
        if computed != txid {
            return Err(StorageError::InvalidMempool(format!(
                "mempool record txid mismatch: key={}, computed={}",
                txid, computed
            )));
        }
        entries.push(MempoolTxRecord {
            txid,
            tx: stored.tx,
            fee: stored.fee,
        });
    }
    entries.sort_by_key(|e| e.txid);
    Ok(MempoolSnapshot {
        network_id,
        entries,
    })
}

pub fn save_pool_ledger_db(path: &Path, snapshot: &PoolLedgerSnapshot) -> Result<(), StorageError> {
    if snapshot.network_id.trim().is_empty() {
        return Err(StorageError::InvalidPoolLedger(
            "network_id must not be empty".to_owned(),
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

    let mut share_dedup = std::collections::HashMap::<String, PoolShareRecord>::new();
    for share in &snapshot.shares {
        if share.share_key.trim().is_empty() {
            return Err(StorageError::InvalidPoolLedger(
                "share_key must not be empty".to_owned(),
            ));
        }
        if share.worker.trim().is_empty() {
            return Err(StorageError::InvalidPoolLedger(
                "share worker must not be empty".to_owned(),
            ));
        }
        share_dedup.insert(share.share_key.clone(), share.clone());
    }
    let mut shares = share_dedup.into_values().collect::<Vec<_>>();
    shares.sort_by(|a, b| a.share_key.cmp(&b.share_key));

    let mut round_dedup = std::collections::HashMap::<u64, PoolRoundRecord>::new();
    for round in &snapshot.rounds {
        round_dedup.insert(round.round_id, round.clone());
    }
    let mut rounds = round_dedup.into_values().collect::<Vec<_>>();
    rounds.sort_by_key(|round| round.round_id);

    let mut worker_dedup = std::collections::HashMap::<String, PoolWorkerAccrualRecord>::new();
    for worker in &snapshot.workers {
        if worker.worker.trim().is_empty() {
            return Err(StorageError::InvalidPoolLedger(
                "worker label must not be empty".to_owned(),
            ));
        }
        worker_dedup.insert(worker.worker.clone(), worker.clone());
    }
    let mut workers = worker_dedup.into_values().collect::<Vec<_>>();
    workers.sort_by(|a, b| a.worker.cmp(&b.worker));

    let mut pending_dedup = std::collections::HashMap::<String, PoolPayoutRecord>::new();
    for payout in &snapshot.pending_payouts {
        if payout.payout_id.trim().is_empty() {
            return Err(StorageError::InvalidPoolLedger(
                "pending payout_id must not be empty".to_owned(),
            ));
        }
        pending_dedup.insert(payout.payout_id.clone(), payout.clone());
    }
    let mut pending_payouts = pending_dedup.into_values().collect::<Vec<_>>();
    pending_payouts.sort_by(|a, b| a.payout_id.cmp(&b.payout_id));

    let mut completed_dedup = std::collections::HashMap::<String, PoolPayoutRecord>::new();
    for payout in &snapshot.completed_payouts {
        if payout.payout_id.trim().is_empty() {
            return Err(StorageError::InvalidPoolLedger(
                "completed payout_id must not be empty".to_owned(),
            ));
        }
        completed_dedup.insert(payout.payout_id.clone(), payout.clone());
    }
    let mut completed_payouts = completed_dedup.into_values().collect::<Vec<_>>();
    completed_payouts.sort_by(|a, b| a.payout_id.cmp(&b.payout_id));

    let db = Database::create(&tmp_path).map_err(|e| StorageError::Db(e.to_string()))?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    {
        let mut meta = write_txn
            .open_table(POOL_META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        let current_round_id_bytes = snapshot.current_round_id.to_le_bytes();
        meta.insert("network_id", snapshot.network_id.as_bytes())
            .map_err(|e| StorageError::Db(e.to_string()))?;
        write_schema_version(&mut meta, POOL_LEDGER_SCHEMA_VERSION)?;
        meta.insert("current_round_id", current_round_id_bytes.as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?;
    }
    {
        let mut table = write_txn
            .open_table(POOL_WORKER_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        for worker in workers {
            let value = bincode::serialize(&worker).map_err(StorageError::Encode)?;
            table
                .insert(worker.worker.as_str(), value.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    {
        let mut table = write_txn
            .open_table(POOL_SHARE_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        for share in shares {
            let value = bincode::serialize(&share).map_err(StorageError::Encode)?;
            table
                .insert(share.share_key.as_str(), value.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    {
        let mut table = write_txn
            .open_table(POOL_ROUND_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        for round in rounds {
            let value = bincode::serialize(&round).map_err(StorageError::Encode)?;
            table
                .insert(round.round_id, value.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    {
        let mut table = write_txn
            .open_table(POOL_PAYOUT_PENDING_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        for payout in pending_payouts {
            let value = bincode::serialize(&payout).map_err(StorageError::Encode)?;
            table
                .insert(payout.payout_id.as_str(), value.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    {
        let mut table = write_txn
            .open_table(POOL_PAYOUT_COMPLETED_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        for payout in completed_payouts {
            let value = bincode::serialize(&payout).map_err(StorageError::Encode)?;
            table
                .insert(payout.payout_id.as_str(), value.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| StorageError::Db(e.to_string()))?;
    atomic_replace_file(&tmp_path, path)?;
    Ok(())
}

pub fn load_pool_ledger_db(path: &Path) -> Result<PoolLedgerSnapshot, StorageError> {
    let db = Database::open(path).map_err(|e| StorageError::Db(e.to_string()))?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StorageError::Db(e.to_string()))?;

    let (network_id, current_round_id) = {
        let meta = read_txn
            .open_table(POOL_META_TABLE)
            .map_err(|e| StorageError::Db(e.to_string()))?;
        check_schema_version(&meta, "pool ledger", POOL_LEDGER_SCHEMA_VERSION, None)?;
        let network_id_raw = meta
            .get("network_id")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("network_id".to_owned()))?;
        let current_round_id_raw = meta
            .get("current_round_id")
            .map_err(|e| StorageError::Db(e.to_string()))?
            .ok_or_else(|| StorageError::MissingMeta("current_round_id".to_owned()))?;
        let network_id = std::str::from_utf8(network_id_raw.value())
            .map_err(StorageError::InvalidUtf8)?
            .to_owned();
        let round_bytes = current_round_id_raw.value();
        if round_bytes.len() != 8 {
            return Err(StorageError::InvalidMetaFormat {
                key: "current_round_id".to_owned(),
                details: format!("expected 8 bytes, got {}", round_bytes.len()),
            });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(round_bytes);
        (network_id, u64::from_le_bytes(buf))
    };

    let worker_table = read_txn
        .open_table(POOL_WORKER_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut workers = Vec::<PoolWorkerAccrualRecord>::new();
    for row in worker_table
        .iter()
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (key, value) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let key_worker = key.value().to_owned();
        let record: PoolWorkerAccrualRecord =
            bincode::deserialize(value.value()).map_err(StorageError::Decode)?;
        if record.worker != key_worker {
            return Err(StorageError::InvalidPoolLedger(format!(
                "worker key mismatch: key={key_worker}, record={}",
                record.worker
            )));
        }
        workers.push(record);
    }
    workers.sort_by(|a, b| a.worker.cmp(&b.worker));

    let share_table = read_txn
        .open_table(POOL_SHARE_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut shares = Vec::<PoolShareRecord>::new();
    for row in share_table
        .iter()
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (key, value) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let key_share = key.value().to_owned();
        let record: PoolShareRecord =
            bincode::deserialize(value.value()).map_err(StorageError::Decode)?;
        if record.share_key != key_share {
            return Err(StorageError::InvalidPoolLedger(format!(
                "share key mismatch: key={key_share}, record={}",
                record.share_key
            )));
        }
        shares.push(record);
    }
    shares.sort_by(|a, b| a.share_key.cmp(&b.share_key));

    let round_table = read_txn
        .open_table(POOL_ROUND_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut rounds = Vec::<PoolRoundRecord>::new();
    for row in round_table
        .iter()
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (key, value) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let round_id = key.value();
        let record: PoolRoundRecord =
            bincode::deserialize(value.value()).map_err(StorageError::Decode)?;
        if record.round_id != round_id {
            return Err(StorageError::InvalidPoolLedger(format!(
                "round key mismatch: key={round_id}, record={}",
                record.round_id
            )));
        }
        rounds.push(record);
    }
    rounds.sort_by_key(|round| round.round_id);

    let pending_table = read_txn
        .open_table(POOL_PAYOUT_PENDING_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut pending_payouts = Vec::<PoolPayoutRecord>::new();
    for row in pending_table
        .iter()
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (key, value) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let payout_id = key.value().to_owned();
        let record: PoolPayoutRecord =
            bincode::deserialize(value.value()).map_err(StorageError::Decode)?;
        if record.payout_id != payout_id {
            return Err(StorageError::InvalidPoolLedger(format!(
                "pending payout key mismatch: key={payout_id}, record={}",
                record.payout_id
            )));
        }
        pending_payouts.push(record);
    }
    pending_payouts.sort_by(|a, b| a.payout_id.cmp(&b.payout_id));

    let completed_table = read_txn
        .open_table(POOL_PAYOUT_COMPLETED_TABLE)
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let mut completed_payouts = Vec::<PoolPayoutRecord>::new();
    for row in completed_table
        .iter()
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        let (key, value) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let payout_id = key.value().to_owned();
        let record: PoolPayoutRecord =
            bincode::deserialize(value.value()).map_err(StorageError::Decode)?;
        if record.payout_id != payout_id {
            return Err(StorageError::InvalidPoolLedger(format!(
                "completed payout key mismatch: key={payout_id}, record={}",
                record.payout_id
            )));
        }
        completed_payouts.push(record);
    }
    completed_payouts.sort_by(|a, b| a.payout_id.cmp(&b.payout_id));

    Ok(PoolLedgerSnapshot {
        network_id,
        current_round_id,
        shares,
        rounds,
        workers,
        pending_payouts,
        completed_payouts,
    })
}

fn atomic_replace_file(tmp_path: &Path, final_path: &Path) -> Result<(), StorageError> {
    fs::rename(tmp_path, final_path).map_err(|source| StorageError::Write {
        path: final_path.display().to_string(),
        source,
    })?;

    let file = fs::File::open(final_path).map_err(|source| StorageError::Write {
        path: final_path.display().to_string(),
        source,
    })?;
    file.sync_all().map_err(|source| StorageError::Write {
        path: final_path.display().to_string(),
        source,
    })?;

    if let Some(parent) = final_path.parent() {
        let dir = fs::File::open(parent).map_err(|source| StorageError::Write {
            path: parent.display().to_string(),
            source,
        })?;
        dir.sync_all().map_err(|source| StorageError::Write {
            path: parent.display().to_string(),
            source,
        })?;
    }

    Ok(())
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

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("chain");
    let suffix = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let file_name = format!("{file_name}.tmp.{pid}.{suffix}");
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
    #[error("invalid peer book: {0}")]
    InvalidPeerBook(String),
    #[error("invalid mempool snapshot: {0}")]
    InvalidMempool(String),
    #[error("invalid pool ledger snapshot: {0}")]
    InvalidPoolLedger(String),
    #[error(
        "{store} has unsupported schema version {found:?} (this build expects {expected}); move the file aside to start fresh"
    )]
    UnsupportedSchema {
        store: &'static str,
        found: Option<u32>,
        expected: u32,
    },
    #[error(
        "refusing to overwrite archive: its tip {disk_tip} at height {disk_height} is not on this writer's chain and has at least as much work"
    )]
    StaleArchiveWriter { disk_tip: Hash256, disk_height: u64 },
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use std::path::PathBuf;

    use scam_consensus::UtxoSet;
    use scam_core::{Block, BlockHeader, Hash256, OutPoint, Target, Transaction, TxIn, TxOut};

    use crate::{
        ChainArchive, ChainStateSnapshot, MempoolSnapshot, MempoolTxRecord, PeerAddressBook,
        PeerAddressRecord, PoolLedgerSnapshot, PoolPayoutRecord, PoolRoundRecord, PoolShareRecord,
        PoolWorkerAccrualRecord, UtxoRecord, load_block_by_hash_db, load_chain_archive_db,
        load_mempool_db, load_peer_book_db, load_pool_ledger_db, load_snapshot, load_snapshot_db,
        save_chain_archive_db, save_mempool_db, save_peer_book_db, save_pool_ledger_db,
        save_snapshot, save_snapshot_db,
    };

    fn temp_test_file(stem: &str, ext: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "scam-{stem}-{}-{ts}-{nonce}.{ext}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn temp_db_path_is_unique_per_call() {
        let base = PathBuf::from("target/storage-temp-path/runtime.redb");
        let one = super::temp_db_path(&base);
        let two = super::temp_db_path(&base);
        assert_ne!(one, two);
        assert_eq!(one.parent(), base.parent());
        assert_eq!(two.parent(), base.parent());
    }

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
                created_time: 0,
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

        let path = temp_test_file("snapshot", "bin");
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
                created_time: 0,
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

        let path = temp_test_file("snapshot", "redb");
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
                created_time: 0,
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

        let path = temp_test_file("chain-archive", "redb");
        save_chain_archive_db(&path, &archive).expect("save archive");
        let loaded = load_chain_archive_db(&path).expect("load archive");
        assert_eq!(loaded.network_id, "devnet");
        assert_eq!(loaded.blocks_by_height.len(), 2);
        assert_eq!(loaded.blocks_by_height[0], genesis);
        assert_eq!(loaded.blocks_by_height[1], block1);
        let _ = std::fs::remove_file(path);
    }

    fn chain_of(parent: Hash256, len: usize, salt: u64) -> Vec<Block> {
        let mut out = Vec::new();
        let mut prev = parent;
        for i in 0..len {
            let block = Block {
                header: BlockHeader {
                    version: 1,
                    prev_block: prev,
                    merkle_root: Hash256::ZERO,
                    timestamp: 1_770_763_200 + i as u64,
                    target: Target::MAX,
                    nonce: salt * 1_000 + i as u64,
                },
                transactions: vec![],
            };
            prev = block.header.block_hash();
            out.push(block);
        }
        out
    }

    fn persist(
        path: &std::path::Path,
        blocks: &[Block],
        work: u64,
    ) -> Result<crate::ArchivePersistOutcome, crate::StorageError> {
        let hashes = blocks
            .iter()
            .map(|b| b.header.block_hash())
            .collect::<Vec<_>>();
        let lookup = |hash: &Hash256| {
            blocks
                .iter()
                .find(|b| b.header.block_hash() == *hash)
                .cloned()
        };
        crate::persist_chain_archive_incremental_db(
            path,
            "devnet",
            &hashes,
            &work.to_be_bytes(),
            &lookup,
        )
    }

    /// S3: persisting writes only blocks above what the archive already has.
    #[test]
    fn incremental_archive_persist_appends_only_new_blocks() {
        let path = temp_test_file("archive-incremental", "redb");
        let chain = chain_of(Hash256::ZERO, 5, 1);
        let first = persist(&path, &chain[..3], 3).expect("first persist");
        assert_eq!(first.blocks_written, 3);
        let second = persist(&path, &chain, 5).expect("second persist");
        assert_eq!(second.first_written_height, Some(3));
        assert_eq!(second.blocks_written, 2);
        let again = persist(&path, &chain, 5).expect("no-op persist");
        assert_eq!(again.blocks_written, 0);
        assert_eq!(again.first_written_height, None);

        let loaded = load_chain_archive_db(&path).expect("load");
        assert_eq!(loaded.blocks_by_height, chain);
        let tip = crate::load_chain_archive_tip_db(&path)
            .expect("tip")
            .expect("some");
        assert_eq!(tip.height, 4);
        assert_eq!(tip.hash, chain[4].header.block_hash());
        let (_, tail) = crate::load_chain_archive_range_db(&path, 3).expect("range");
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].0, 3);
        let _ = std::fs::remove_file(path);
    }

    /// S1: a writer whose chain is behind (or on a lighter fork) must not be
    /// able to roll the shared archive back.
    #[test]
    fn incremental_archive_persist_refuses_stale_writer_but_accepts_heavier_fork() {
        let path = temp_test_file("archive-stale-writer", "redb");
        let main = chain_of(Hash256::ZERO, 5, 2);
        persist(&path, &main, 5).expect("relay persists height 4");

        // A process still at height 2 tries to persist its view.
        let err = persist(&path, &main[..3], 3).expect_err("stale prefix must be refused");
        assert!(matches!(
            err,
            crate::StorageError::StaleArchiveWriter { .. }
        ));
        // A lighter fork from height 1 is refused too.
        let mut light = main[..2].to_vec();
        light.extend(chain_of(main[1].header.block_hash(), 2, 3));
        assert!(matches!(
            persist(&path, &light, 4),
            Err(crate::StorageError::StaleArchiveWriter { .. })
        ));
        assert_eq!(
            load_chain_archive_db(&path).expect("load").blocks_by_height,
            main
        );

        // A heavier, shorter fork is a legitimate reorg: index rewritten and
        // entries above the new tip removed.
        let mut heavy = main[..2].to_vec();
        heavy.extend(chain_of(main[1].header.block_hash(), 2, 4));
        let outcome = persist(&path, &heavy, 9).expect("heavier fork wins");
        assert_eq!(outcome.first_written_height, Some(2));
        assert_eq!(
            load_chain_archive_db(&path).expect("load").blocks_by_height,
            heavy
        );
        let _ = std::fs::remove_file(path);
    }

    /// S7: stores carry a schema version; a file with an unknown version
    /// is refused instead of being misread.
    #[test]
    fn stores_record_and_enforce_schema_version() {
        let path = temp_test_file("archive-schema", "redb");
        let chain = chain_of(Hash256::ZERO, 2, 7);
        persist(&path, &chain, 2).expect("persist");
        load_chain_archive_db(&path).expect("current version loads");
        {
            let db = redb::Database::open(&path).expect("open");
            let txn = db.begin_write().expect("txn");
            {
                let mut meta = txn.open_table(crate::META_TABLE).expect("meta");
                meta.insert(crate::SCHEMA_VERSION_KEY, 99u32.to_le_bytes().as_slice())
                    .expect("insert");
            }
            txn.commit().expect("commit");
        }
        assert!(matches!(
            load_chain_archive_db(&path),
            Err(crate::StorageError::UnsupportedSchema {
                found: Some(99),
                ..
            })
        ));
        let _ = std::fs::remove_file(path);

        // A pool ledger without a version is a v1 ledger: refused.
        let ledger_path = temp_test_file("ledger-schema", "redb");
        {
            let db = redb::Database::create(&ledger_path).expect("create");
            let txn = db.begin_write().expect("txn");
            {
                let mut meta = txn.open_table(crate::POOL_META_TABLE).expect("meta");
                meta.insert("network_id", b"devnet".as_slice())
                    .expect("net");
                meta.insert("current_round_id", 0u64.to_le_bytes().as_slice())
                    .expect("round");
            }
            txn.commit().expect("commit");
        }
        assert!(matches!(
            load_pool_ledger_db(&ledger_path),
            Err(crate::StorageError::UnsupportedSchema { found: None, .. })
        ));
        let _ = std::fs::remove_file(ledger_path);
    }

    #[test]
    fn chain_archive_db_load_block_by_hash_roundtrip() {
        let genesis = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::from_hex(
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .expect("hash"),
                timestamp: 1_770_763_200,
                target: Target::MAX,
                nonce: 11,
            },
            transactions: vec![],
        };
        let block1 = Block {
            header: BlockHeader {
                version: 1,
                prev_block: genesis.header.block_hash(),
                merkle_root: Hash256::from_hex(
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                )
                .expect("hash"),
                timestamp: 1_770_763_320,
                target: Target::MAX,
                nonce: 22,
            },
            transactions: vec![],
        };
        let archive = ChainArchive {
            network_id: "devnet".to_owned(),
            blocks_by_height: vec![genesis.clone(), block1.clone()],
        };

        let path = temp_test_file("chain-archive-by-hash", "redb");
        save_chain_archive_db(&path, &archive).expect("save archive");

        let block_hash = block1.header.block_hash();
        let loaded = load_block_by_hash_db(&path, block_hash).expect("load by hash");
        assert_eq!(loaded, Some(block1));

        let missing =
            load_block_by_hash_db(&path, Hash256::from_hex(&"11".repeat(32)).expect("hash"))
                .expect("load missing hash");
        assert_eq!(missing, None);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_book_db_roundtrip() {
        let peer_book = PeerAddressBook {
            network_id: "devnet".to_owned(),
            peers: vec![
                PeerAddressRecord {
                    address: "127.0.0.1:8333".to_owned(),
                    last_seen_unix_sec: 1_770_763_200,
                    ban_score: 0,
                },
                PeerAddressRecord {
                    address: "192.168.1.10:8333".to_owned(),
                    last_seen_unix_sec: 1_770_763_210,
                    ban_score: 2,
                },
                // Duplicate address should be deduplicated by save path.
                PeerAddressRecord {
                    address: "127.0.0.1:8333".to_owned(),
                    last_seen_unix_sec: 1_770_763_300,
                    ban_score: 5,
                },
            ],
        };

        let path = temp_test_file("peer-book", "redb");
        save_peer_book_db(&path, &peer_book).expect("save peer book");
        let loaded = load_peer_book_db(&path).expect("load peer book");
        assert_eq!(loaded.network_id, "devnet");
        assert_eq!(loaded.peers.len(), 2);
        assert_eq!(loaded.peers[0].address, "127.0.0.1:8333");
        assert_eq!(loaded.peers[0].ban_score, 5);
        assert_eq!(loaded.peers[1].address, "192.168.1.10:8333");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_book_rejects_empty_address() {
        let peer_book = PeerAddressBook {
            network_id: "devnet".to_owned(),
            peers: vec![PeerAddressRecord {
                address: "   ".to_owned(),
                last_seen_unix_sec: 0,
                ban_score: 0,
            }],
        };
        let path = temp_test_file("peer-book-invalid", "redb");
        let err = save_peer_book_db(&path, &peer_book).expect_err("must reject empty address");
        assert!(matches!(err, crate::StorageError::InvalidPeerBook(_)));
    }

    fn sample_tx(seed: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([seed; 32]),
                    vout: seed as u32,
                },
                signature: vec![seed; 64],
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [seed; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn mempool_snapshot_db_roundtrip() {
        let tx_a = sample_tx(1);
        let tx_b = sample_tx(2);
        let snapshot = MempoolSnapshot {
            network_id: "devnet".to_owned(),
            entries: vec![
                MempoolTxRecord {
                    txid: tx_a.txid(),
                    tx: tx_a.clone(),
                    fee: 10,
                },
                MempoolTxRecord {
                    txid: tx_b.txid(),
                    tx: tx_b.clone(),
                    fee: 20,
                },
                // Duplicate txid should be deduped by save path (last one wins).
                MempoolTxRecord {
                    txid: tx_a.txid(),
                    tx: tx_a,
                    fee: 50,
                },
            ],
        };

        let path = temp_test_file("mempool", "redb");
        save_mempool_db(&path, &snapshot).expect("save mempool");
        let loaded = load_mempool_db(&path).expect("load mempool");
        assert_eq!(loaded.network_id, "devnet");
        assert_eq!(loaded.entries.len(), 2);
        let entry_a = loaded
            .entries
            .iter()
            .find(|entry| entry.txid == sample_tx(1).txid())
            .expect("tx a");
        assert_eq!(entry_a.fee, 50);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mempool_snapshot_rejects_txid_mismatch() {
        let tx = sample_tx(9);
        let snapshot = MempoolSnapshot {
            network_id: "devnet".to_owned(),
            entries: vec![MempoolTxRecord {
                txid: Hash256([0u8; 32]),
                tx,
                fee: 1,
            }],
        };
        let path = temp_test_file("mempool-invalid", "redb");
        let err = save_mempool_db(&path, &snapshot).expect_err("must reject mismatch");
        assert!(matches!(err, crate::StorageError::InvalidMempool(_)));
    }

    #[test]
    fn pool_ledger_db_roundtrip_and_dedup() {
        let snapshot = PoolLedgerSnapshot {
            network_id: "devnet".to_owned(),
            current_round_id: 7,
            shares: vec![
                PoolShareRecord {
                    share_key: "1:2:3:4".to_owned(),
                    worker: "miner.a".to_owned(),
                    timestamp_unix_sec: 1_770_763_200,
                    channel_id: 1,
                    job_id: 2,
                    nonce: 3,
                    ntime: 4,
                    expected_hashes: 12_000.0,
                    accepted: true,
                    is_block: false,
                },
                // duplicate key: last one should win
                PoolShareRecord {
                    share_key: "1:2:3:4".to_owned(),
                    worker: "miner.a".to_owned(),
                    timestamp_unix_sec: 1_770_763_201,
                    channel_id: 1,
                    job_id: 2,
                    nonce: 3,
                    ntime: 4,
                    expected_hashes: 22_000.0,
                    accepted: true,
                    is_block: true,
                },
            ],
            rounds: vec![
                PoolRoundRecord {
                    round_id: 6,
                    start_height: 100,
                    start_tip_hash: Hash256([0x11; 32]),
                    start_unix_sec: 1_770_763_100,
                    end_height: Some(101),
                    end_tip_hash: Some(Hash256([0x22; 32])),
                    end_unix_sec: Some(1_770_763_220),
                    closed_by_worker: Some("miner.a".to_owned()),
                    found_block_hash: Some(Hash256([0x33; 32])),
                    found_block_reward_atomic: 5_000_000_000,
                    orphaned: false,
                    pplns_credits: Vec::new(),
                },
                PoolRoundRecord {
                    round_id: 7,
                    start_height: 101,
                    start_tip_hash: Hash256([0x22; 32]),
                    start_unix_sec: 1_770_763_220,
                    end_height: None,
                    end_tip_hash: None,
                    end_unix_sec: None,
                    closed_by_worker: None,
                    found_block_hash: None,
                    found_block_reward_atomic: 0,
                    orphaned: false,
                    pplns_credits: Vec::new(),
                },
            ],
            workers: vec![
                PoolWorkerAccrualRecord {
                    worker: "miner.a".to_owned(),
                    accepted_total: 2,
                    rejected_total: 1,
                    blocks_found_total: 1,
                    expected_hashes_accumulated: 34_000.0,
                    pplns_accrual_atomic: 10_000,
                    pplns_settled_atomic: 0,
                    pps_accrual_atomic: 2_000,
                    paid_total_atomic: 500,
                    last_share_unix_sec: 1_770_763_201,
                },
                PoolWorkerAccrualRecord {
                    worker: "miner.a".to_owned(),
                    accepted_total: 3,
                    rejected_total: 1,
                    blocks_found_total: 2,
                    expected_hashes_accumulated: 44_000.0,
                    pplns_accrual_atomic: 20_000,
                    pplns_settled_atomic: 0,
                    pps_accrual_atomic: 4_000,
                    paid_total_atomic: 1_000,
                    last_share_unix_sec: 1_770_763_202,
                },
            ],
            pending_payouts: vec![PoolPayoutRecord {
                payout_id: "p-1".to_owned(),
                worker: "miner.a".to_owned(),
                amount_atomic: 1_500,
                created_unix_sec: 1_770_763_230,
                submitted_txid_hex: None,
                confirmed: false,
            }],
            completed_payouts: vec![PoolPayoutRecord {
                payout_id: "p-0".to_owned(),
                worker: "miner.b".to_owned(),
                amount_atomic: 800,
                created_unix_sec: 1_770_763_120,
                submitted_txid_hex: Some("aa".repeat(32)),
                confirmed: true,
            }],
        };

        let path = temp_test_file("pool-ledger", "redb");
        save_pool_ledger_db(&path, &snapshot).expect("save pool ledger");
        let loaded = load_pool_ledger_db(&path).expect("load pool ledger");
        assert_eq!(loaded.network_id, "devnet");
        assert_eq!(loaded.current_round_id, 7);
        assert_eq!(loaded.shares.len(), 1);
        assert!(loaded.shares[0].is_block);
        assert_eq!(loaded.workers.len(), 1);
        assert_eq!(loaded.workers[0].accepted_total, 3);
        assert_eq!(loaded.rounds.len(), 2);
        assert_eq!(loaded.pending_payouts.len(), 1);
        assert_eq!(loaded.completed_payouts.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn pool_ledger_rejects_empty_identity_fields() {
        let path = temp_test_file("pool-ledger-invalid", "redb");
        let bad = PoolLedgerSnapshot {
            network_id: "".to_owned(),
            current_round_id: 0,
            shares: vec![],
            rounds: vec![],
            workers: vec![],
            pending_payouts: vec![],
            completed_payouts: vec![],
        };
        let err = save_pool_ledger_db(&path, &bad).expect_err("must reject invalid pool ledger");
        assert!(matches!(err, crate::StorageError::InvalidPoolLedger(_)));
    }
}
