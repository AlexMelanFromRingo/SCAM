use std::collections::{HashMap, HashSet};

use scam_core::{Hash256, OutPoint, Transaction};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Mempool {
    max_txs: usize,
    min_relay_fee_per_kb: u64,
    txs: HashMap<Hash256, MempoolEntry>,
    spent_outpoints: HashMap<OutPoint, Hash256>,
}

#[derive(Debug, Clone)]
struct MempoolEntry {
    tx: Transaction,
    fee: u64,
    serialized_size: usize,
}

impl Mempool {
    pub fn new(max_txs: usize) -> Result<Self, MempoolError> {
        Self::with_policy(max_txs, 0)
    }

    pub fn with_policy(max_txs: usize, min_relay_fee_per_kb: u64) -> Result<Self, MempoolError> {
        if max_txs == 0 {
            return Err(MempoolError::InvalidLimit(
                "max_txs must be greater than 0".to_owned(),
            ));
        }

        Ok(Self {
            max_txs,
            min_relay_fee_per_kb,
            txs: HashMap::new(),
            spent_outpoints: HashMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
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

    pub fn insert(&mut self, tx: Transaction) -> Result<InsertOutcome, MempoolError> {
        self.insert_with_fee(tx, 0)
    }

    pub fn min_required_fee(&self, tx: &Transaction) -> Result<u64, MempoolError> {
        required_fee_for_size(tx.encode_for_hash().len(), self.min_relay_fee_per_kb)
    }

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
        if self.txs.contains_key(&txid) {
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

        let mut conflict_txid: Option<Hash256> = None;
        for input in &tx.inputs {
            if let Some(existing_txid) = self.spent_outpoints.get(&input.prev_out) {
                conflict_txid = Some(*existing_txid);
                break;
            }
        }

        if let Some(existing_txid) = conflict_txid {
            if txid < existing_txid {
                let removed = self.remove_with_descendants(existing_txid);
                self.txs.insert(
                    txid,
                    MempoolEntry {
                        tx,
                        fee,
                        serialized_size,
                    },
                );
                self.rebuild_spent_outpoints();
                return Ok(InsertOutcome::Replaced {
                    inserted: txid,
                    removed,
                });
            }
            return Ok(InsertOutcome::RejectedHigherHash {
                inserted: txid,
                existing: existing_txid,
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

    fn remove_with_descendants(&mut self, root_txid: Hash256) -> Vec<Hash256> {
        let mut to_remove = HashSet::<Hash256>::new();
        to_remove.insert(root_txid);

        loop {
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
        for txid in &removed {
            self.txs.remove(txid);
        }
        removed
    }

    fn rebuild_spent_outpoints(&mut self) {
        self.spent_outpoints.clear();
        for (txid, entry) in &self.txs {
            for input in &entry.tx.inputs {
                self.spent_outpoints.insert(input.prev_out.clone(), *txid);
            }
        }
    }
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
    RejectedHigherHash {
        inserted: Hash256,
        existing: Hash256,
    },
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MempoolError {
    #[error("{0}")]
    InvalidLimit(String),
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
}

#[cfg(test)]
mod tests {
    use scam_core::{OutPoint, Transaction, TxIn, TxOut};

    use crate::{InsertOutcome, Mempool, MempoolError};

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

    #[test]
    fn conflicting_tx_keeps_lower_hash() {
        let mut mempool = Mempool::new(100).expect("mempool must initialize");
        let parent = [9u8; 32];

        // Build two conflicts and force ordering by txid.
        let tx_a = mk_tx(parent, 0, b"A", 1);
        let tx_b = mk_tx(parent, 0, b"BBBBBBBBBBBBBBBBBBBBBBBB", 2);

        let a_id = tx_a.txid();
        let b_id = tx_b.txid();

        let (low, high) = if a_id < b_id {
            (tx_a, tx_b)
        } else {
            (tx_b, tx_a)
        };

        let low_id = low.txid();
        let high_id = high.txid();

        let first = mempool.insert(high).expect("insert should succeed");
        assert!(matches!(first, InsertOutcome::Accepted { .. }));

        let second = mempool.insert(low).expect("insert should succeed");
        assert!(matches!(
            second,
            InsertOutcome::Replaced { inserted, .. } if inserted == low_id
        ));
        assert!(mempool.contains(&low_id));
        assert!(!mempool.contains(&high_id));
    }

    #[test]
    fn replacement_removes_descendants() {
        let mut mempool = Mempool::new(100).expect("mempool must initialize");
        let root = [7u8; 32];
        let parent_old = mk_tx(root, 0, b"parent-old", 10);
        let parent_new = mk_tx(root, 0, b"parent-new-replacement", 11);

        let parent_old_id = parent_old.txid();
        let parent_new_id = parent_new.txid();

        let child = mk_tx(parent_old_id.0, 0, b"child", 12);
        let child_id = child.txid();

        mempool.insert(parent_old).expect("insert parent old");
        mempool.insert(child).expect("insert child");

        let (winner, loser) = if parent_new_id < parent_old_id {
            (parent_new_id, parent_old_id)
        } else {
            (parent_old_id, parent_new_id)
        };

        // If generated ids do not match replacement direction, invert insertion order.
        if winner == parent_new_id {
            let outcome = mempool.insert(parent_new).expect("insert replacement");
            assert!(matches!(outcome, InsertOutcome::Replaced { .. }));
            assert!(mempool.contains(&parent_new_id));
            assert!(!mempool.contains(&loser));
            assert!(!mempool.contains(&child_id));
        } else {
            // In this case the new txid was not lower; expect rejection and existing graph intact.
            let outcome = mempool.insert(parent_new).expect("insert replacement");
            assert!(matches!(outcome, InsertOutcome::RejectedHigherHash { .. }));
            assert!(mempool.contains(&parent_old_id));
            assert!(mempool.contains(&child_id));
        }
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
}
