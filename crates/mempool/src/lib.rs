use std::collections::{HashMap, HashSet};

use scam_core::{Hash256, OutPoint, Transaction};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Mempool {
    max_txs: usize,
    txs: HashMap<Hash256, Transaction>,
    spent_outpoints: HashMap<OutPoint, Hash256>,
}

impl Mempool {
    pub fn new(max_txs: usize) -> Result<Self, MempoolError> {
        if max_txs == 0 {
            return Err(MempoolError::InvalidLimit(
                "max_txs must be greater than 0".to_owned(),
            ));
        }

        Ok(Self {
            max_txs,
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
        self.txs.get(txid)
    }

    pub fn contains(&self, txid: &Hash256) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn insert(&mut self, tx: Transaction) -> Result<InsertOutcome, MempoolError> {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Ok(InsertOutcome::AlreadyPresent { txid });
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
                self.txs.insert(txid, tx);
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
            return Err(MempoolError::Full {
                limit: self.max_txs,
                incoming: txid,
            });
        }

        self.txs.insert(txid, tx);
        self.rebuild_spent_outpoints();
        Ok(InsertOutcome::Accepted { txid })
    }

    fn remove_with_descendants(&mut self, root_txid: Hash256) -> Vec<Hash256> {
        let mut to_remove = HashSet::<Hash256>::new();
        to_remove.insert(root_txid);

        loop {
            let mut changed = false;
            for (txid, tx) in &self.txs {
                if to_remove.contains(txid) {
                    continue;
                }
                if tx
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
        for (txid, tx) in &self.txs {
            for input in &tx.inputs {
                self.spent_outpoints.insert(input.prev_out.clone(), *txid);
            }
        }
    }
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
}

#[cfg(test)]
mod tests {
    use scam_core::{OutPoint, Transaction, TxIn, TxOut};

    use crate::{InsertOutcome, Mempool};

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
}
