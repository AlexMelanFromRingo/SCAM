use std::collections::{HashMap, HashSet, VecDeque};

use scam_core::{Hash256, OutPoint, Transaction};
use thiserror::Error;

const DEFAULT_MIN_REPLACEMENT_FEE_DELTA: u64 = 1;
const DEFAULT_MAX_REPLACEMENT_DESCENDANTS: usize = 25;

#[derive(Debug, Clone)]
pub struct Mempool {
    max_txs: usize,
    min_relay_fee_per_kb: u64,
    min_replacement_fee_delta: u64,
    max_replacement_descendants: usize,
    revision: u64,
    txs: HashMap<Hash256, MempoolEntry>,
    spent_outpoints: HashMap<OutPoint, Hash256>,
    telemetry: MempoolTelemetry,
}

#[derive(Debug, Clone)]
struct MempoolEntry {
    tx: Transaction,
    fee: u64,
    serialized_size: usize,
}

#[derive(Clone, Debug)]
struct OrphanEntry {
    tx: Transaction,
    fee: u64,
    missing_outpoints: HashSet<OutPoint>,
    added_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyOrphanTx {
    pub txid: Hash256,
    pub tx: Transaction,
    pub fee: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrphanInsertOutcome {
    Accepted { txid: Hash256 },
    AlreadyPresent { txid: Hash256 },
    AcceptedWithEviction { inserted: Hash256, evicted: Hash256 },
}

#[derive(Clone, Debug)]
pub struct OrphanPool {
    max_txs: usize,
    ttl_secs: u64,
    entries: HashMap<Hash256, OrphanEntry>,
    by_missing_outpoint: HashMap<OutPoint, HashSet<Hash256>>,
    insertion_order: VecDeque<Hash256>,
    telemetry: OrphanPoolTelemetry,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MempoolTelemetry {
    pub accepted_total: u64,
    pub replaced_total: u64,
    pub removed_by_replacement_total: u64,
    pub evicted_total: u64,
    pub removed_by_block_total: u64,
    pub rejected_conflict_total: u64,
    pub duplicate_total: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrphanPoolTelemetry {
    pub accepted_total: u64,
    pub evicted_total: u64,
    pub expired_total: u64,
    pub promoted_total: u64,
    pub duplicate_total: u64,
}

impl Mempool {
    pub fn new(max_txs: usize) -> Result<Self, MempoolError> {
        Self::with_policy(max_txs, 0)
    }

    pub fn with_policy(max_txs: usize, min_relay_fee_per_kb: u64) -> Result<Self, MempoolError> {
        Self::with_policy_and_replacement(
            max_txs,
            min_relay_fee_per_kb,
            DEFAULT_MIN_REPLACEMENT_FEE_DELTA,
            DEFAULT_MAX_REPLACEMENT_DESCENDANTS,
        )
    }

    pub fn with_policy_and_replacement(
        max_txs: usize,
        min_relay_fee_per_kb: u64,
        min_replacement_fee_delta: u64,
        max_replacement_descendants: usize,
    ) -> Result<Self, MempoolError> {
        if max_txs == 0 {
            return Err(MempoolError::InvalidLimit(
                "max_txs must be greater than 0".to_owned(),
            ));
        }
        if max_replacement_descendants == 0 {
            return Err(MempoolError::InvalidLimit(
                "max_replacement_descendants must be greater than 0".to_owned(),
            ));
        }

        Ok(Self {
            max_txs,
            min_relay_fee_per_kb,
            min_replacement_fee_delta,
            max_replacement_descendants,
            revision: 0,
            txs: HashMap::new(),
            spent_outpoints: HashMap::new(),
            telemetry: MempoolTelemetry::default(),
        })
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn telemetry(&self) -> MempoolTelemetry {
        self.telemetry
    }

    pub fn get(&self, txid: &Hash256) -> Option<&Transaction> {
        self.txs.get(txid).map(|entry| &entry.tx)
    }

    pub fn contains(&self, txid: &Hash256) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn fee(&self, txid: &Hash256) -> Option<u64> {
        self.txs.get(txid).map(|entry| entry.fee)
    }

    pub fn get_with_fee(&self, txid: &Hash256) -> Option<(&Transaction, u64)> {
        self.txs.get(txid).map(|entry| (&entry.tx, entry.fee))
    }

    pub fn remove_confirmed_txids(&mut self, txids: &[Hash256]) -> Vec<Hash256> {
        if txids.is_empty() {
            return Vec::new();
        }

        let mut removed = Vec::<Hash256>::new();
        let mut seen = HashSet::<Hash256>::new();
        for txid in txids {
            if !seen.insert(*txid) {
                continue;
            }
            if self.txs.remove(txid).is_some() {
                removed.push(*txid);
            }
        }
        if !removed.is_empty() {
            self.rebuild_spent_outpoints();
            self.bump_revision();
            self.telemetry.removed_by_block_total = self
                .telemetry
                .removed_by_block_total
                .saturating_add(removed.len() as u64);
            removed.sort_unstable();
        }
        removed
    }

    pub fn insert(&mut self, tx: Transaction) -> Result<InsertOutcome, MempoolError> {
        self.insert_with_fee(tx, 0)
    }

    pub fn min_required_fee(&self, tx: &Transaction) -> Result<u64, MempoolError> {
        required_fee_for_size(tx.encode_for_hash().len(), self.min_relay_fee_per_kb)
    }

    /// Returns independent tx feerate ordering.
    ///
    /// CPFP package/ancestor scoring is applied by the miner template builder.
    pub fn txids_by_feerate_desc(&self) -> Vec<Hash256> {
        let mut ranked = self
            .txs
            .iter()
            .map(|(txid, entry)| {
                let fee_rate_key = feerate_key(entry.fee, entry.serialized_size);
                (*txid, fee_rate_key)
            })
            .collect::<Vec<_>>();
        ranked.sort_unstable_by(|(txid_a, rate_a), (txid_b, rate_b)| {
            rate_b.cmp(rate_a).then_with(|| txid_a.cmp(txid_b))
        });
        ranked.into_iter().map(|(txid, _)| txid).collect()
    }

    pub fn insert_with_fee(
        &mut self,
        tx: Transaction,
        fee: u64,
    ) -> Result<InsertOutcome, MempoolError> {
        let txid = tx.txid();
        validate_transaction_for_mempool(&tx, txid)?;
        if self.txs.contains_key(&txid) {
            self.telemetry.duplicate_total = self.telemetry.duplicate_total.saturating_add(1);
            return Ok(InsertOutcome::AlreadyPresent { txid });
        }
        let serialized_size = tx.encode_for_hash().len();
        let required_fee = required_fee_for_size(serialized_size, self.min_relay_fee_per_kb)?;
        if fee < required_fee {
            return Err(MempoolError::FeeTooLow {
                incoming: txid,
                fee,
                required_fee,
                size_bytes: serialized_size,
                min_relay_fee_per_kb: self.min_relay_fee_per_kb,
            });
        }

        let mut conflict_txids = HashSet::<Hash256>::new();
        for input in &tx.inputs {
            if let Some(existing_txid) = self.spent_outpoints.get(&input.prev_out) {
                conflict_txids.insert(*existing_txid);
            }
        }

        if !conflict_txids.is_empty() {
            if conflict_txids.len() > 1 {
                let mut conflicts = conflict_txids.into_iter().collect::<Vec<_>>();
                conflicts.sort_unstable();
                return Err(MempoolError::MultipleConflicts {
                    incoming: txid,
                    conflicts,
                });
            }
            let existing_txid = *conflict_txids
                .iter()
                .next()
                .expect("non-empty set by branch");
            let existing = self
                .txs
                .get(&existing_txid)
                .expect("spent_outpoints must point to mempool tx");
            let existing_rate = feerate_key(existing.fee, existing.serialized_size);
            let incoming_rate = feerate_key(fee, serialized_size);
            if incoming_rate <= existing_rate {
                self.telemetry.rejected_conflict_total =
                    self.telemetry.rejected_conflict_total.saturating_add(1);
                return Ok(InsertOutcome::RejectedConflictInsufficientFeerate {
                    inserted: txid,
                    existing: existing_txid,
                    incoming_feerate: incoming_rate,
                    existing_feerate: existing_rate,
                });
            }

            let required_fee = existing
                .fee
                .checked_add(self.min_replacement_fee_delta)
                .ok_or_else(|| {
                    MempoolError::InvalidLimit(
                        "replacement required fee overflow in mempool policy".to_owned(),
                    )
                })?;
            if fee < required_fee {
                self.telemetry.rejected_conflict_total =
                    self.telemetry.rejected_conflict_total.saturating_add(1);
                return Ok(InsertOutcome::RejectedConflictInsufficientFee {
                    inserted: txid,
                    existing: existing_txid,
                    incoming_fee: fee,
                    required_fee,
                });
            }

            let replacement_set = self.collect_replacement_set(existing_txid);
            let descendant_count = replacement_set.len().saturating_sub(1);
            if descendant_count > self.max_replacement_descendants {
                return Err(MempoolError::ReplacementTooManyDescendants {
                    incoming: txid,
                    existing: existing_txid,
                    descendants: descendant_count,
                    limit: self.max_replacement_descendants,
                });
            }

            let removed = self.remove_txids(replacement_set);
            self.txs.insert(
                txid,
                MempoolEntry {
                    tx,
                    fee,
                    serialized_size,
                },
            );
            self.rebuild_spent_outpoints();
            self.bump_revision();
            self.telemetry.replaced_total = self.telemetry.replaced_total.saturating_add(1);
            self.telemetry.removed_by_replacement_total = self
                .telemetry
                .removed_by_replacement_total
                .saturating_add(removed.len() as u64);
            return Ok(InsertOutcome::Replaced {
                inserted: txid,
                removed,
            });
        }

        if self.txs.len() >= self.max_txs {
            let incoming_rate = feerate_key(fee, serialized_size);
            let Some((victim_txid, victim_rate)) = self.lowest_feerate_txid() else {
                return Err(MempoolError::Full {
                    limit: self.max_txs,
                    incoming: txid,
                });
            };
            if incoming_rate <= victim_rate {
                return Err(MempoolError::Full {
                    limit: self.max_txs,
                    incoming: txid,
                });
            }

            let removed = self.remove_with_descendants(victim_txid);
            self.txs.insert(
                txid,
                MempoolEntry {
                    tx,
                    fee,
                    serialized_size,
                },
            );
            self.rebuild_spent_outpoints();
            self.bump_revision();
            self.telemetry.accepted_total = self.telemetry.accepted_total.saturating_add(1);
            self.telemetry.evicted_total = self
                .telemetry
                .evicted_total
                .saturating_add(removed.len() as u64);
            return Ok(InsertOutcome::AcceptedWithEviction {
                inserted: txid,
                removed,
            });
        }

        self.txs.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                serialized_size,
            },
        );
        self.rebuild_spent_outpoints();
        self.bump_revision();
        self.telemetry.accepted_total = self.telemetry.accepted_total.saturating_add(1);
        Ok(InsertOutcome::Accepted { txid })
    }

    fn lowest_feerate_txid(&self) -> Option<(Hash256, u128)> {
        self.txs
            .iter()
            .map(|(txid, entry)| (*txid, feerate_key(entry.fee, entry.serialized_size)))
            .min_by(|(txid_a, rate_a), (txid_b, rate_b)| {
                rate_a.cmp(rate_b).then_with(|| txid_b.cmp(txid_a))
            })
    }

    fn collect_replacement_set(&self, root_txid: Hash256) -> Vec<Hash256> {
        let mut to_remove = HashSet::<Hash256>::new();
        to_remove.insert(root_txid);

        // Safety bound: each pass must add at least one txid or terminate.
        for _ in 0..=self.txs.len() {
            let mut changed = false;
            for (txid, entry) in &self.txs {
                if to_remove.contains(txid) {
                    continue;
                }
                if entry
                    .tx
                    .inputs
                    .iter()
                    .any(|input| to_remove.contains(&input.prev_out.txid))
                {
                    to_remove.insert(*txid);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        let mut removed = to_remove.into_iter().collect::<Vec<_>>();
        removed.sort_unstable();
        removed
    }

    fn remove_txids(&mut self, txids: Vec<Hash256>) -> Vec<Hash256> {
        for txid in &txids {
            self.txs.remove(txid);
        }
        txids
    }

    fn remove_with_descendants(&mut self, root_txid: Hash256) -> Vec<Hash256> {
        let removed = self.collect_replacement_set(root_txid);
        self.remove_txids(removed)
    }

    fn rebuild_spent_outpoints(&mut self) {
        self.spent_outpoints.clear();
        for (txid, entry) in &self.txs {
            for input in &entry.tx.inputs {
                self.spent_outpoints.insert(input.prev_out.clone(), *txid);
            }
        }
    }

    fn bump_revision(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }
}

impl OrphanPool {
    pub fn new(max_txs: usize, ttl_secs: u64) -> Result<Self, MempoolError> {
        if max_txs == 0 {
            return Err(MempoolError::InvalidLimit(
                "orphan pool max_txs must be greater than 0".to_owned(),
            ));
        }
        if ttl_secs == 0 {
            return Err(MempoolError::InvalidLimit(
                "orphan pool ttl_secs must be greater than 0".to_owned(),
            ));
        }
        Ok(Self {
            max_txs,
            ttl_secs,
            entries: HashMap::new(),
            by_missing_outpoint: HashMap::new(),
            insertion_order: VecDeque::new(),
            telemetry: OrphanPoolTelemetry::default(),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, txid: &Hash256) -> bool {
        self.entries.contains_key(txid)
    }

    pub fn telemetry(&self) -> OrphanPoolTelemetry {
        self.telemetry
    }

    pub fn insert(
        &mut self,
        tx: Transaction,
        fee: u64,
        missing_outpoints: Vec<OutPoint>,
        now_unix_sec: u64,
    ) -> Result<OrphanInsertOutcome, MempoolError> {
        let txid = tx.txid();
        validate_transaction_for_mempool(&tx, txid)?;
        if missing_outpoints.is_empty() {
            return Err(MempoolError::OrphanMissingOutpoints { txid });
        }

        if self.entries.contains_key(&txid) {
            self.telemetry.duplicate_total = self.telemetry.duplicate_total.saturating_add(1);
            return Ok(OrphanInsertOutcome::AlreadyPresent { txid });
        }

        let missing_set = missing_outpoints.into_iter().collect::<HashSet<_>>();
        let mut evicted = None;
        if self.entries.len() >= self.max_txs {
            while let Some(oldest) = self.insertion_order.pop_front() {
                if self.remove_entry(oldest).is_some() {
                    evicted = Some(oldest);
                    break;
                }
            }
        }

        self.entries.insert(
            txid,
            OrphanEntry {
                tx,
                fee,
                missing_outpoints: missing_set.clone(),
                added_at: now_unix_sec,
            },
        );
        self.insertion_order.push_back(txid);
        for outpoint in missing_set {
            self.by_missing_outpoint
                .entry(outpoint)
                .or_default()
                .insert(txid);
        }

        if let Some(evicted) = evicted {
            self.telemetry.accepted_total = self.telemetry.accepted_total.saturating_add(1);
            self.telemetry.evicted_total = self.telemetry.evicted_total.saturating_add(1);
            return Ok(OrphanInsertOutcome::AcceptedWithEviction {
                inserted: txid,
                evicted,
            });
        }
        self.telemetry.accepted_total = self.telemetry.accepted_total.saturating_add(1);
        Ok(OrphanInsertOutcome::Accepted { txid })
    }

    pub fn expire(&mut self, now_unix_sec: u64) -> usize {
        let expired = self
            .entries
            .iter()
            .filter_map(|(txid, entry)| {
                let deadline = entry.added_at.saturating_add(self.ttl_secs);
                if now_unix_sec >= deadline {
                    Some(*txid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for txid in &expired {
            self.remove_entry(*txid);
        }
        self.telemetry.expired_total = self
            .telemetry
            .expired_total
            .saturating_add(expired.len() as u64);
        expired.len()
    }

    pub fn resolve_outpoint(&mut self, outpoint: &OutPoint) -> Vec<ReadyOrphanTx> {
        let waiting = self
            .by_missing_outpoint
            .remove(outpoint)
            .unwrap_or_default();
        if waiting.is_empty() {
            return Vec::new();
        }

        let mut ready_txids = Vec::<Hash256>::new();
        for txid in waiting {
            if let Some(entry) = self.entries.get_mut(&txid) {
                entry.missing_outpoints.remove(outpoint);
                if entry.missing_outpoints.is_empty() {
                    ready_txids.push(txid);
                }
            }
        }

        let mut ready = Vec::<ReadyOrphanTx>::new();
        for txid in ready_txids {
            if let Some(entry) = self.remove_entry(txid) {
                ready.push(ReadyOrphanTx {
                    txid,
                    tx: entry.tx,
                    fee: entry.fee,
                });
            }
        }
        ready.sort_unstable_by(|a, b| a.txid.cmp(&b.txid));
        self.telemetry.promoted_total = self
            .telemetry
            .promoted_total
            .saturating_add(ready.len() as u64);
        ready
    }

    fn remove_entry(&mut self, txid: Hash256) -> Option<OrphanEntry> {
        let entry = self.entries.remove(&txid)?;
        for outpoint in &entry.missing_outpoints {
            let mut should_remove_key = false;
            if let Some(waiters) = self.by_missing_outpoint.get_mut(outpoint) {
                waiters.remove(&txid);
                should_remove_key = waiters.is_empty();
            }
            if should_remove_key {
                self.by_missing_outpoint.remove(outpoint);
            }
        }
        Some(entry)
    }
}

fn validate_transaction_for_mempool(tx: &Transaction, txid: Hash256) -> Result<(), MempoolError> {
    if tx.is_coinbase() {
        return Err(MempoolError::CoinbaseNotAllowed { txid });
    }
    if tx.inputs.is_empty() {
        return Err(MempoolError::NoInputs { txid });
    }
    if tx.outputs.is_empty() {
        return Err(MempoolError::NoOutputs { txid });
    }

    let mut seen_inputs = HashSet::<OutPoint>::new();
    for (input_index, input) in tx.inputs.iter().enumerate() {
        if input.prev_out.is_coinbase() {
            return Err(MempoolError::CoinbasePrevoutInRegularTx { txid, input_index });
        }
        if !seen_inputs.insert(input.prev_out.clone()) {
            return Err(MempoolError::DuplicateInput {
                txid,
                outpoint: input.prev_out.clone(),
            });
        }
        if input.signature.is_empty() {
            return Err(MempoolError::EmptySignature { txid, input_index });
        }
        let pubkey_len = input.pubkey_compressed.len();
        if pubkey_len != 33 {
            return Err(MempoolError::InvalidPubkeyLength {
                txid,
                input_index,
                len: pubkey_len,
            });
        }
        let prefix = input.pubkey_compressed[0];
        if prefix != 0x02 && prefix != 0x03 {
            return Err(MempoolError::InvalidPubkeyPrefix {
                txid,
                input_index,
                prefix,
            });
        }
    }

    for (output_index, output) in tx.outputs.iter().enumerate() {
        if output.value == 0 {
            return Err(MempoolError::ZeroValueOutput { txid, output_index });
        }
    }

    Ok(())
}

fn required_fee_for_size(
    size_bytes: usize,
    min_relay_fee_per_kb: u64,
) -> Result<u64, MempoolError> {
    if min_relay_fee_per_kb == 0 {
        return Ok(0);
    }
    let numerator = (size_bytes as u128)
        .checked_mul(min_relay_fee_per_kb as u128)
        .and_then(|n| n.checked_add(999))
        .ok_or_else(|| {
            MempoolError::InvalidLimit("fee calculation overflow in mempool policy".to_owned())
        })?;
    let fee = numerator / 1000;
    u64::try_from(fee)
        .map_err(|_| MempoolError::InvalidLimit("required fee does not fit into u64".to_owned()))
}

fn feerate_key(fee: u64, serialized_size: usize) -> u128 {
    ((fee as u128) * 1000) / (serialized_size as u128)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InsertOutcome {
    Accepted {
        txid: Hash256,
    },
    AlreadyPresent {
        txid: Hash256,
    },
    Replaced {
        inserted: Hash256,
        removed: Vec<Hash256>,
    },
    AcceptedWithEviction {
        inserted: Hash256,
        removed: Vec<Hash256>,
    },
    RejectedConflictInsufficientFee {
        inserted: Hash256,
        existing: Hash256,
        incoming_fee: u64,
        required_fee: u64,
    },
    RejectedConflictInsufficientFeerate {
        inserted: Hash256,
        existing: Hash256,
        incoming_feerate: u128,
        existing_feerate: u128,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MempoolInventoryDelta {
    pub announced_txids: Vec<Hash256>,
    pub removed_txids: Vec<Hash256>,
}

impl InsertOutcome {
    pub fn inventory_delta(&self) -> MempoolInventoryDelta {
        match self {
            InsertOutcome::Accepted { txid } => MempoolInventoryDelta {
                announced_txids: vec![*txid],
                removed_txids: Vec::new(),
            },
            InsertOutcome::Replaced { inserted, removed } => MempoolInventoryDelta {
                announced_txids: vec![*inserted],
                removed_txids: removed.clone(),
            },
            InsertOutcome::AcceptedWithEviction { inserted, removed } => MempoolInventoryDelta {
                announced_txids: vec![*inserted],
                removed_txids: removed.clone(),
            },
            InsertOutcome::AlreadyPresent { .. }
            | InsertOutcome::RejectedConflictInsufficientFee { .. }
            | InsertOutcome::RejectedConflictInsufficientFeerate { .. } => MempoolInventoryDelta {
                announced_txids: Vec::new(),
                removed_txids: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MempoolError {
    #[error("{0}")]
    InvalidLimit(String),
    #[error("coinbase transaction {txid} cannot enter mempool")]
    CoinbaseNotAllowed { txid: Hash256 },
    #[error("transaction {txid} has no inputs")]
    NoInputs { txid: Hash256 },
    #[error("transaction {txid} has no outputs")]
    NoOutputs { txid: Hash256 },
    #[error("transaction {txid} has coinbase prevout in input #{input_index}")]
    CoinbasePrevoutInRegularTx { txid: Hash256, input_index: usize },
    #[error("transaction {txid} has duplicate input {outpoint:?}")]
    DuplicateInput { txid: Hash256, outpoint: OutPoint },
    #[error("transaction {txid} has empty signature in input #{input_index}")]
    EmptySignature { txid: Hash256, input_index: usize },
    #[error("transaction {txid} has invalid pubkey length {len} in input #{input_index}")]
    InvalidPubkeyLength {
        txid: Hash256,
        input_index: usize,
        len: usize,
    },
    #[error("transaction {txid} has invalid pubkey prefix 0x{prefix:02x} in input #{input_index}")]
    InvalidPubkeyPrefix {
        txid: Hash256,
        input_index: usize,
        prefix: u8,
    },
    #[error("transaction {txid} has zero-value output at index #{output_index}")]
    ZeroValueOutput { txid: Hash256, output_index: usize },
    #[error("orphan transaction {txid} must include at least one missing outpoint")]
    OrphanMissingOutpoints { txid: Hash256 },
    #[error("mempool full (limit={limit}), incoming txid={incoming}")]
    Full { limit: usize, incoming: Hash256 },
    #[error(
        "relay fee too low for {incoming}: fee={fee}, required={required_fee}, size={size_bytes}B, min_relay_fee_per_kb={min_relay_fee_per_kb}"
    )]
    FeeTooLow {
        incoming: Hash256,
        fee: u64,
        required_fee: u64,
        size_bytes: usize,
        min_relay_fee_per_kb: u64,
    },
    #[error("incoming tx {incoming} conflicts with multiple mempool txs: {conflicts:?}")]
    MultipleConflicts {
        incoming: Hash256,
        conflicts: Vec<Hash256>,
    },
    #[error(
        "replacement for {existing} rejected: descendants={descendants} exceeds limit={limit} (incoming={incoming})"
    )]
    ReplacementTooManyDescendants {
        incoming: Hash256,
        existing: Hash256,
        descendants: usize,
        limit: usize,
    },
}

#[cfg(test)]
mod tests {
    use scam_core::{OutPoint, Transaction, TxIn, TxOut};

    use crate::{
        InsertOutcome, Mempool, MempoolError, MempoolInventoryDelta, OrphanInsertOutcome,
        OrphanPool,
    };

    fn mk_tx(
        spends_txid: [u8; 32],
        spends_vout: u32,
        signature: &[u8],
        output_seed: u8,
    ) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: scam_core::Hash256(spends_txid),
                    vout: spends_vout,
                },
                signature: signature.to_vec(),
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [output_seed; 20],
            }],
            lock_time: 0,
        }
    }

    fn mk_two_input_tx(
        first_spend: ([u8; 32], u32),
        second_spend: ([u8; 32], u32),
        signature: &[u8],
        output_seed: u8,
    ) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: OutPoint {
                        txid: scam_core::Hash256(first_spend.0),
                        vout: first_spend.1,
                    },
                    signature: signature.to_vec(),
                    pubkey_compressed: vec![2u8; 33],
                    sequence: 0,
                },
                TxIn {
                    prev_out: OutPoint {
                        txid: scam_core::Hash256(second_spend.0),
                        vout: second_spend.1,
                    },
                    signature: signature.to_vec(),
                    pubkey_compressed: vec![3u8; 33],
                    sequence: 0,
                },
            ],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [output_seed; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn conflicting_tx_prefers_higher_feerate() {
        let mut mempool =
            Mempool::with_policy_and_replacement(100, 0, 1, 25).expect("mempool must initialize");
        let parent = [9u8; 32];
        let tx_low_fee = mk_tx(parent, 0, b"same-size-a", 1);
        let tx_high_fee = mk_tx(parent, 0, b"same-size-b", 2);
        let low_id = tx_low_fee.txid();
        let high_id = tx_high_fee.txid();

        let first = mempool
            .insert_with_fee(tx_low_fee, 10)
            .expect("insert should succeed");
        assert!(matches!(first, InsertOutcome::Accepted { .. }));

        let second = mempool
            .insert_with_fee(tx_high_fee, 50)
            .expect("insert should succeed");
        assert!(matches!(
            second,
            InsertOutcome::Replaced { inserted, .. } if inserted == high_id
        ));
        assert!(mempool.contains(&high_id));
        assert!(!mempool.contains(&low_id));
    }

    #[test]
    fn replacement_removes_descendants() {
        let mut mempool =
            Mempool::with_policy_and_replacement(100, 0, 1, 25).expect("mempool must initialize");
        let root = [7u8; 32];
        let parent_old = mk_tx(root, 0, b"parent-old", 10);
        let parent_new = mk_tx(root, 0, b"parent-new-replacement", 11);

        let parent_old_id = parent_old.txid();
        let parent_new_id = parent_new.txid();

        let child = mk_tx(parent_old_id.0, 0, b"child", 12);
        let child_id = child.txid();

        mempool.insert(parent_old).expect("insert parent old");
        mempool.insert(child).expect("insert child");

        let outcome = mempool
            .insert_with_fee(parent_new, 100)
            .expect("insert replacement");
        assert!(matches!(outcome, InsertOutcome::Replaced { .. }));
        assert!(mempool.contains(&parent_new_id));
        assert!(!mempool.contains(&parent_old_id));
        assert!(!mempool.contains(&child_id));
    }

    #[test]
    fn replacement_removes_long_descendant_chain_without_hanging() {
        let mut mempool =
            Mempool::with_policy_and_replacement(256, 0, 1, 200).expect("mempool must initialize");
        let root = [15u8; 32];
        let parent_old = mk_tx(root, 0, b"parent-old", 10);
        let parent_old_id = parent_old.txid();
        mempool
            .insert_with_fee(parent_old, 10)
            .expect("insert parent old");

        let mut chain = vec![parent_old_id];
        for i in 0..40u8 {
            let prev = chain.last().copied().expect("previous txid");
            let sig = format!("child-{i}").into_bytes();
            let child = mk_tx(prev.0, 0, &sig, i);
            let child_id = child.txid();
            mempool.insert_with_fee(child, 10).expect("insert child");
            chain.push(child_id);
        }

        let parent_new = mk_tx(root, 0, b"parent-new", 11);
        let parent_new_id = parent_new.txid();
        let outcome = mempool
            .insert_with_fee(parent_new, 500)
            .expect("replacement must succeed");

        let removed = match outcome {
            InsertOutcome::Replaced { removed, .. } => removed,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert_eq!(removed.len(), 41);
        assert!(mempool.contains(&parent_new_id));
        for txid in chain {
            assert!(!mempool.contains(&txid));
        }
    }

    #[test]
    fn replacement_rejects_if_fee_delta_too_small() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 10, 25).expect("mempool");
        let root = [31u8; 32];
        let old_tx = mk_tx(root, 0, b"same-size-a", 1);
        let new_tx = mk_tx(root, 0, b"same-size-b", 2);
        let old_id = old_tx.txid();
        let new_id = new_tx.txid();

        mempool.insert_with_fee(old_tx, 100).expect("insert old");
        let outcome = mempool
            .insert_with_fee(new_tx, 105)
            .expect("replacement evaluation");
        assert!(matches!(
            outcome,
            InsertOutcome::RejectedConflictInsufficientFee {
                inserted,
                existing,
                incoming_fee: 105,
                required_fee: 110
            } if inserted == new_id && existing == old_id
        ));
        assert!(mempool.contains(&old_id));
        assert!(!mempool.contains(&new_id));
    }

    #[test]
    fn replacement_rejects_if_feerate_not_higher() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 1, 25).expect("mempool");
        let root = [41u8; 32];
        let old_tx = mk_tx(root, 0, b"same-size-a", 1);
        let new_tx = mk_tx(root, 0, b"same-size-b", 2);
        let old_id = old_tx.txid();
        let new_id = new_tx.txid();

        mempool.insert_with_fee(old_tx, 100).expect("insert old");
        let outcome = mempool
            .insert_with_fee(new_tx, 99)
            .expect("replacement evaluation");
        assert!(matches!(
            outcome,
            InsertOutcome::RejectedConflictInsufficientFeerate {
                inserted,
                existing,
                ..
            } if inserted == new_id && existing == old_id
        ));
        assert!(mempool.contains(&old_id));
        assert!(!mempool.contains(&new_id));
    }

    #[test]
    fn replacement_rejects_when_descendant_limit_exceeded() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 1, 1).expect("mempool");
        let root = [51u8; 32];
        let parent_old = mk_tx(root, 0, b"parent-old", 1);
        let parent_old_id = parent_old.txid();
        let child_1 = mk_tx(parent_old_id.0, 0, b"child-1", 2);
        let child_1_id = child_1.txid();
        let child_2 = mk_tx(child_1_id.0, 0, b"child-2", 3);
        let parent_new = mk_tx(root, 0, b"parent-new", 4);
        let parent_new_id = parent_new.txid();

        mempool
            .insert_with_fee(parent_old, 10)
            .expect("insert parent");
        mempool.insert_with_fee(child_1, 10).expect("insert child1");
        mempool.insert_with_fee(child_2, 10).expect("insert child2");

        let err = mempool
            .insert_with_fee(parent_new, 100)
            .expect_err("replacement should fail due to descendant limit");
        assert!(matches!(
            err,
            MempoolError::ReplacementTooManyDescendants {
                incoming,
                descendants: 2,
                limit: 1,
                ..
            } if incoming == parent_new_id
        ));
        assert!(mempool.contains(&parent_old_id));
    }

    #[test]
    fn replacement_accepts_when_fee_equals_required_threshold() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 10, 25).expect("mempool");
        let root = [53u8; 32];
        let old_tx = mk_tx(root, 0, b"same-size-a", 1);
        let new_tx = mk_tx(root, 0, b"same-size-b", 2);
        let old_id = old_tx.txid();
        let new_id = new_tx.txid();

        mempool.insert_with_fee(old_tx, 100).expect("insert old");
        let outcome = mempool
            .insert_with_fee(new_tx, 110)
            .expect("replacement evaluation");
        assert!(matches!(
            outcome,
            InsertOutcome::Replaced { inserted, .. } if inserted == new_id
        ));
        assert!(mempool.contains(&new_id));
        assert!(!mempool.contains(&old_id));
    }

    #[test]
    fn replacement_accepts_when_descendant_count_equals_limit() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 1, 2).expect("mempool");
        let root = [54u8; 32];
        let parent_old = mk_tx(root, 0, b"parent-old", 1);
        let parent_old_id = parent_old.txid();
        let child_1 = mk_tx(parent_old_id.0, 0, b"child-1", 2);
        let child_1_id = child_1.txid();
        let child_2 = mk_tx(child_1_id.0, 0, b"child-2", 3);
        let parent_new = mk_tx(root, 0, b"parent-new", 4);
        let parent_new_id = parent_new.txid();

        mempool
            .insert_with_fee(parent_old, 10)
            .expect("insert parent");
        mempool.insert_with_fee(child_1, 10).expect("insert child1");
        mempool.insert_with_fee(child_2, 10).expect("insert child2");

        let outcome = mempool
            .insert_with_fee(parent_new, 100)
            .expect("replacement should pass at descendant limit");
        assert!(matches!(
            outcome,
            InsertOutcome::Replaced { inserted, .. } if inserted == parent_new_id
        ));
        assert!(mempool.contains(&parent_new_id));
        assert!(!mempool.contains(&parent_old_id));
    }

    #[test]
    fn replacement_rejects_if_incoming_conflicts_with_multiple_transactions() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 1, 25).expect("mempool");
        let tx_a = mk_tx([61u8; 32], 0, b"a", 1);
        let tx_b = mk_tx([62u8; 32], 0, b"b", 2);
        let tx_a_id = tx_a.txid();
        let tx_b_id = tx_b.txid();
        mempool.insert_with_fee(tx_a, 10).expect("insert a");
        mempool.insert_with_fee(tx_b, 10).expect("insert b");
        let mut expected_conflicts = vec![tx_a_id, tx_b_id];
        expected_conflicts.sort_unstable();

        let tx_conflict = mk_two_input_tx(([61u8; 32], 0), ([62u8; 32], 0), b"replace-both", 3);
        let conflict_id = tx_conflict.txid();
        let err = mempool
            .insert_with_fee(tx_conflict, 500)
            .expect_err("must reject multi-conflict replacement");

        assert!(matches!(
            err,
            MempoolError::MultipleConflicts {
                incoming,
                conflicts,
            } if incoming == conflict_id && conflicts == expected_conflicts
        ));
    }

    #[test]
    fn relay_fee_policy_rejects_low_fee_tx() {
        let mut mempool = Mempool::with_policy(100, 1_000).expect("mempool must initialize");
        let tx = mk_tx([5u8; 32], 0, b"fee-test", 1);
        let required = mempool.min_required_fee(&tx).expect("required fee");
        assert!(required > 0);

        let err = mempool
            .insert_with_fee(tx.clone(), required - 1)
            .expect_err("must reject low fee");
        assert!(matches!(err, MempoolError::FeeTooLow { .. }));

        let accepted = mempool
            .insert_with_fee(tx, required)
            .expect("must accept fee at threshold");
        assert!(matches!(accepted, InsertOutcome::Accepted { .. }));
    }

    #[test]
    fn txids_are_sorted_by_feerate_desc() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool must initialize");
        let tx_low = mk_tx([1u8; 32], 0, b"same-size-a", 1);
        let tx_mid = mk_tx([2u8; 32], 0, b"same-size-b", 2);
        let tx_high = mk_tx([3u8; 32], 0, b"same-size-c", 3);

        let low_id = tx_low.txid();
        let mid_id = tx_mid.txid();
        let high_id = tx_high.txid();

        mempool.insert_with_fee(tx_low, 10).expect("insert low");
        mempool.insert_with_fee(tx_mid, 20).expect("insert mid");
        mempool.insert_with_fee(tx_high, 50).expect("insert high");

        let ranked = mempool.txids_by_feerate_desc();
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0], high_id);
        assert_eq!(ranked[1], mid_id);
        assert_eq!(ranked[2], low_id);
    }

    #[test]
    fn full_mempool_evicts_lowest_feerate_tx() {
        let mut mempool = Mempool::with_policy(2, 0).expect("mempool");
        let tx_low = mk_tx([10u8; 32], 0, b"same-size-a", 1);
        let tx_high = mk_tx([11u8; 32], 0, b"same-size-b", 2);
        let tx_mid = mk_tx([12u8; 32], 0, b"same-size-c", 3);
        let low_id = tx_low.txid();
        let high_id = tx_high.txid();
        let mid_id = tx_mid.txid();

        mempool.insert_with_fee(tx_low, 10).expect("insert low");
        mempool.insert_with_fee(tx_high, 100).expect("insert high");
        let outcome = mempool.insert_with_fee(tx_mid, 50).expect("insert mid");
        assert!(matches!(
            outcome,
            InsertOutcome::AcceptedWithEviction { inserted, .. } if inserted == mid_id
        ));
        assert_eq!(mempool.len(), 2);
        assert!(!mempool.contains(&low_id));
        assert!(mempool.contains(&mid_id));
        assert!(mempool.contains(&high_id));
    }

    #[test]
    fn full_mempool_rejects_tx_with_lower_feerate() {
        let mut mempool = Mempool::with_policy(2, 0).expect("mempool");
        let tx_a = mk_tx([21u8; 32], 0, b"same-size-a", 1);
        let tx_b = mk_tx([22u8; 32], 0, b"same-size-b", 2);
        let tx_c = mk_tx([23u8; 32], 0, b"same-size-c", 3);
        let a_id = tx_a.txid();
        let b_id = tx_b.txid();
        let c_id = tx_c.txid();

        mempool.insert_with_fee(tx_a, 40).expect("insert a");
        mempool.insert_with_fee(tx_b, 30).expect("insert b");
        let err = mempool
            .insert_with_fee(tx_c, 5)
            .expect_err("must reject low feerate");
        assert!(matches!(err, MempoolError::Full { .. }));
        assert_eq!(mempool.len(), 2);
        assert!(mempool.contains(&a_id));
        assert!(mempool.contains(&b_id));
        assert!(!mempool.contains(&c_id));
    }

    #[test]
    fn coinbase_transaction_is_rejected() {
        let mut mempool = Mempool::with_policy(10, 0).expect("mempool");
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"coinbase".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [9u8; 20],
            }],
            lock_time: 0,
        };
        let txid = tx.txid();
        let err = mempool
            .insert(tx)
            .expect_err("coinbase tx must be rejected");
        assert!(matches!(err, MempoolError::CoinbaseNotAllowed { txid: got } if got == txid));
    }

    #[test]
    fn zero_value_output_is_rejected() {
        let mut mempool = Mempool::with_policy(10, 0).expect("mempool");
        let mut tx = mk_tx([61u8; 32], 0, b"sig", 7);
        tx.outputs[0].value = 0;
        let txid = tx.txid();
        let err = mempool
            .insert(tx)
            .expect_err("zero output must be rejected");
        assert!(matches!(
            err,
            MempoolError::ZeroValueOutput {
                txid: got,
                output_index: 0
            } if got == txid
        ));
    }

    #[test]
    fn duplicate_inputs_are_rejected() {
        let mut mempool = Mempool::with_policy(10, 0).expect("mempool");
        let prev_out = OutPoint {
            txid: scam_core::Hash256([71u8; 32]),
            vout: 0,
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: prev_out.clone(),
                    signature: b"a".to_vec(),
                    pubkey_compressed: vec![2u8; 33],
                    sequence: 0,
                },
                TxIn {
                    prev_out: prev_out.clone(),
                    signature: b"b".to_vec(),
                    pubkey_compressed: vec![3u8; 33],
                    sequence: 0,
                },
            ],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [1u8; 20],
            }],
            lock_time: 0,
        };
        let txid = tx.txid();
        let err = mempool
            .insert(tx)
            .expect_err("duplicate inputs must be rejected");
        assert!(matches!(
            err,
            MempoolError::DuplicateInput {
                txid: got,
                outpoint
            } if got == txid && outpoint == prev_out
        ));
    }

    #[test]
    fn invalid_pubkey_prefix_is_rejected() {
        let mut mempool = Mempool::with_policy(10, 0).expect("mempool");
        let mut tx = mk_tx([81u8; 32], 0, b"sig", 2);
        tx.inputs[0].pubkey_compressed = vec![4u8; 33];
        let txid = tx.txid();

        let err = mempool
            .insert(tx)
            .expect_err("invalid pubkey prefix must be rejected");
        assert!(matches!(
            err,
            MempoolError::InvalidPubkeyPrefix {
                txid: got,
                input_index: 0,
                prefix: 4
            } if got == txid
        ));
    }

    #[test]
    fn orphan_pool_promotes_tx_when_all_dependencies_resolved() {
        let mut pool = OrphanPool::new(10, 60).expect("pool");
        let dep_a = OutPoint {
            txid: scam_core::Hash256([91u8; 32]),
            vout: 0,
        };
        let dep_b = OutPoint {
            txid: scam_core::Hash256([92u8; 32]),
            vout: 1,
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: dep_a.clone(),
                    signature: b"a".to_vec(),
                    pubkey_compressed: vec![2u8; 33],
                    sequence: 0,
                },
                TxIn {
                    prev_out: dep_b.clone(),
                    signature: b"b".to_vec(),
                    pubkey_compressed: vec![3u8; 33],
                    sequence: 0,
                },
            ],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [4u8; 20],
            }],
            lock_time: 0,
        };
        let txid = tx.txid();
        let insert = pool
            .insert(tx, 7, vec![dep_a.clone(), dep_b.clone()], 100)
            .expect("insert orphan");
        assert!(matches!(insert, OrphanInsertOutcome::Accepted { txid: got } if got == txid));

        let first = pool.resolve_outpoint(&dep_a);
        assert!(first.is_empty(), "still missing one input");
        assert!(pool.contains(&txid));

        let second = pool.resolve_outpoint(&dep_b);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].txid, txid);
        assert_eq!(second[0].fee, 7);
        assert!(pool.is_empty());
    }

    #[test]
    fn orphan_pool_evicts_oldest_entry_when_full() {
        let mut pool = OrphanPool::new(1, 60).expect("pool");
        let dep_a = OutPoint {
            txid: scam_core::Hash256([101u8; 32]),
            vout: 0,
        };
        let dep_b = OutPoint {
            txid: scam_core::Hash256([102u8; 32]),
            vout: 0,
        };
        let tx_a = mk_tx([111u8; 32], 0, b"a", 1);
        let tx_b = mk_tx([112u8; 32], 0, b"b", 2);
        let tx_a_id = tx_a.txid();
        let tx_b_id = tx_b.txid();

        pool.insert(tx_a, 1, vec![dep_a], 10).expect("insert a");
        let outcome = pool
            .insert(tx_b, 1, vec![dep_b], 11)
            .expect("insert b with eviction");
        assert!(matches!(
            outcome,
            OrphanInsertOutcome::AcceptedWithEviction {
                inserted,
                evicted
            } if inserted == tx_b_id && evicted == tx_a_id
        ));
        assert!(!pool.contains(&tx_a_id));
        assert!(pool.contains(&tx_b_id));
    }

    #[test]
    fn orphan_pool_expires_old_entries() {
        let mut pool = OrphanPool::new(10, 5).expect("pool");
        let dep = OutPoint {
            txid: scam_core::Hash256([121u8; 32]),
            vout: 0,
        };
        let tx = mk_tx([122u8; 32], 0, b"a", 1);
        let txid = tx.txid();
        pool.insert(tx, 1, vec![dep], 100).expect("insert");

        let removed_before = pool.expire(104);
        assert_eq!(removed_before, 0);
        assert!(pool.contains(&txid));

        let removed_after = pool.expire(105);
        assert_eq!(removed_after, 1);
        assert!(!pool.contains(&txid));
    }

    #[test]
    fn orphan_pool_rejects_empty_missing_dependency_list() {
        let mut pool = OrphanPool::new(10, 60).expect("pool");
        let tx = mk_tx([131u8; 32], 0, b"a", 1);
        let txid = tx.txid();
        let err = pool
            .insert(tx, 1, Vec::new(), 0)
            .expect_err("must reject empty dependency list");
        assert!(matches!(err, MempoolError::OrphanMissingOutpoints { txid: got } if got == txid));
    }

    #[test]
    fn mempool_revision_increments_only_on_state_change() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 1, 25).expect("mempool");
        let start = mempool.revision();
        let tx_a = mk_tx([141u8; 32], 0, b"a", 1);
        let tx_b = mk_tx([141u8; 32], 0, b"b", 2);

        mempool.insert_with_fee(tx_a, 10).expect("insert a");
        assert!(mempool.revision() > start);
        let after_insert = mempool.revision();

        // Already present -> no state change.
        let existing = mempool
            .insert_with_fee(mk_tx([141u8; 32], 0, b"a", 1), 10)
            .expect("already present");
        assert!(matches!(existing, InsertOutcome::AlreadyPresent { .. }));
        assert_eq!(mempool.revision(), after_insert);

        // Rejected replacement (lower fee) -> no state change.
        let rejected = mempool
            .insert_with_fee(tx_b.clone(), 5)
            .expect("replacement check");
        assert!(matches!(
            rejected,
            InsertOutcome::RejectedConflictInsufficientFeerate { .. }
        ));
        assert_eq!(mempool.revision(), after_insert);

        // Accepted replacement -> revision bump.
        let replaced = mempool
            .insert_with_fee(tx_b, 100)
            .expect("replacement accepted");
        assert!(matches!(replaced, InsertOutcome::Replaced { .. }));
        assert!(mempool.revision() > after_insert);
    }

    #[test]
    fn inventory_delta_reflects_insert_replace_and_reject_paths() {
        let accepted = InsertOutcome::Accepted {
            txid: scam_core::Hash256([1u8; 32]),
        };
        assert_eq!(
            accepted.inventory_delta(),
            MempoolInventoryDelta {
                announced_txids: vec![scam_core::Hash256([1u8; 32])],
                removed_txids: Vec::new()
            }
        );

        let replaced = InsertOutcome::Replaced {
            inserted: scam_core::Hash256([2u8; 32]),
            removed: vec![scam_core::Hash256([3u8; 32]), scam_core::Hash256([4u8; 32])],
        };
        assert_eq!(
            replaced.inventory_delta(),
            MempoolInventoryDelta {
                announced_txids: vec![scam_core::Hash256([2u8; 32])],
                removed_txids: vec![scam_core::Hash256([3u8; 32]), scam_core::Hash256([4u8; 32])]
            }
        );

        let rejected = InsertOutcome::RejectedConflictInsufficientFeerate {
            inserted: scam_core::Hash256([5u8; 32]),
            existing: scam_core::Hash256([6u8; 32]),
            incoming_feerate: 10,
            existing_feerate: 11,
        };
        assert_eq!(
            rejected.inventory_delta(),
            MempoolInventoryDelta {
                announced_txids: Vec::new(),
                removed_txids: Vec::new()
            }
        );
    }

    #[test]
    fn mempool_telemetry_tracks_replacement_and_conflict_rejections() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 1, 25).expect("mempool");
        let tx_low = mk_tx([151u8; 32], 0, b"low", 1);
        let tx_high = mk_tx([151u8; 32], 0, b"high", 2);
        let tx_reject = mk_tx([151u8; 32], 0, b"reject", 3);

        mempool.insert_with_fee(tx_low, 10).expect("insert low");
        let rejected = mempool
            .insert_with_fee(tx_reject, 10)
            .expect("replacement feerate check");
        assert!(matches!(
            rejected,
            InsertOutcome::RejectedConflictInsufficientFeerate { .. }
        ));
        let replaced = mempool
            .insert_with_fee(tx_high, 100)
            .expect("replacement accepted");
        assert!(matches!(replaced, InsertOutcome::Replaced { .. }));

        let telemetry = mempool.telemetry();
        assert_eq!(telemetry.accepted_total, 1);
        assert_eq!(telemetry.replaced_total, 1);
        assert_eq!(telemetry.removed_by_replacement_total, 1);
        assert_eq!(telemetry.rejected_conflict_total, 1);
    }

    #[test]
    fn orphan_pool_telemetry_tracks_churn() {
        let mut pool = OrphanPool::new(1, 5).expect("pool");
        let dep_a = OutPoint {
            txid: scam_core::Hash256([161u8; 32]),
            vout: 0,
        };
        let dep_b = OutPoint {
            txid: scam_core::Hash256([162u8; 32]),
            vout: 0,
        };
        let tx_a = mk_tx([163u8; 32], 0, b"a", 1);
        let tx_b = mk_tx([164u8; 32], 0, b"b", 2);

        let _ = pool
            .insert(tx_a.clone(), 1, vec![dep_a.clone()], 100)
            .expect("insert a");
        let _ = pool
            .insert(tx_a, 1, vec![dep_a.clone()], 101)
            .expect("duplicate a");
        let _ = pool
            .insert(tx_b, 1, vec![dep_b], 102)
            .expect("insert b with eviction");
        let _ = pool.resolve_outpoint(&dep_a);
        let _ = pool.expire(200);

        let telemetry = pool.telemetry();
        assert_eq!(telemetry.accepted_total, 2);
        assert_eq!(telemetry.duplicate_total, 1);
        assert_eq!(telemetry.evicted_total, 1);
        assert_eq!(telemetry.promoted_total, 0);
        assert_eq!(telemetry.expired_total, 1);
    }

    #[test]
    fn remove_confirmed_txids_updates_pool_and_telemetry() {
        let mut mempool = Mempool::with_policy_and_replacement(100, 0, 1, 25).expect("mempool");
        let tx_a = mk_tx([171u8; 32], 0, b"a", 1);
        let tx_b = mk_tx([172u8; 32], 0, b"b", 2);
        let tx_a_id = tx_a.txid();
        let tx_b_id = tx_b.txid();
        let missing = scam_core::Hash256([199u8; 32]);

        let _ = mempool.insert_with_fee(tx_a, 10).expect("insert a");
        let _ = mempool.insert_with_fee(tx_b, 10).expect("insert b");
        let removed = mempool.remove_confirmed_txids(&[tx_b_id, missing, tx_a_id, tx_b_id]);

        assert_eq!(removed, vec![tx_a_id, tx_b_id]);
        assert!(mempool.is_empty());
        let telemetry = mempool.telemetry();
        assert_eq!(telemetry.removed_by_block_total, 2);
    }
}
