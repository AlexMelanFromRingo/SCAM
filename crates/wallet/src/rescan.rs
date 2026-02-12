use std::collections::HashMap;

use scam_core::{Block, OutPoint};
use thiserror::Error;

use crate::address::{AddressError, key_hash20_from_compressed_pubkey};
use crate::signer::{DeriveKeyError, derive_wallet_key};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchedKey {
    pub account: u32,
    pub index: u32,
    pub pubkey_compressed: [u8; 33],
    pub key_hash20: [u8; 20],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedUtxo {
    pub outpoint: OutPoint,
    pub account: u32,
    pub index: u32,
    pub value: u64,
    pub key_hash20: [u8; 20],
    pub created_height: u64,
    pub is_coinbase: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescanBalance {
    pub account: u32,
    pub index: u32,
    pub key_hash20: [u8; 20],
    pub unspent_count: usize,
    pub total: u128,
    pub spendable: u128,
    pub immature: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescanReport {
    pub scanned_blocks: u64,
    pub tip_height: u64,
    pub watched_keys: usize,
    pub total_received: u128,
    pub total_spent: u128,
    pub unspent_total: u128,
    pub spendable_total: u128,
    pub immature_total: u128,
    pub unspent_count: usize,
    pub balances: Vec<RescanBalance>,
    pub unspent: Vec<OwnedUtxo>,
}

pub fn derive_watched_keys(
    seed: &[u8],
    account: u32,
    start_index: u32,
    end_index: u32,
) -> Result<Vec<WatchedKey>, RescanError> {
    if start_index > end_index {
        return Err(RescanError::InvalidRange {
            start_index,
            end_index,
        });
    }

    let mut watched = Vec::with_capacity((end_index - start_index + 1) as usize);
    for index in start_index..=end_index {
        let key = derive_wallet_key(seed, account, index)?;
        let pubkey_compressed = key.pubkey_compressed();
        let key_hash20 = key_hash20_from_compressed_pubkey(pubkey_compressed)?;
        watched.push(WatchedKey {
            account,
            index,
            pubkey_compressed,
            key_hash20,
        });
    }
    Ok(watched)
}

pub fn rescan_blocks<'a, I>(
    watched: &[WatchedKey],
    blocks: I,
    coinbase_maturity: u64,
) -> RescanReport
where
    I: IntoIterator<Item = (u64, &'a Block)>,
{
    let mut watched_lookup = HashMap::<[u8; 20], &WatchedKey>::with_capacity(watched.len());
    for key in watched {
        watched_lookup.insert(key.key_hash20, key);
    }

    let mut unspent = HashMap::<OutPoint, OwnedUtxo>::new();
    let mut total_received = 0u128;
    let mut total_spent = 0u128;
    let mut scanned_blocks = 0u64;
    let mut tip_height = 0u64;

    for (height, block) in blocks {
        scanned_blocks = scanned_blocks.saturating_add(1);
        tip_height = tip_height.max(height);

        for tx in &block.transactions {
            for input in &tx.inputs {
                if let Some(owned) = unspent.remove(&input.prev_out) {
                    total_spent = total_spent.saturating_add(owned.value as u128);
                }
            }

            let txid = tx.txid();
            let is_coinbase = tx.is_coinbase();
            for (vout, output) in tx.outputs.iter().enumerate() {
                let Some(owner) = watched_lookup.get(&output.key_hash20).copied() else {
                    continue;
                };

                total_received = total_received.saturating_add(output.value as u128);
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                unspent.insert(
                    outpoint.clone(),
                    OwnedUtxo {
                        outpoint,
                        account: owner.account,
                        index: owner.index,
                        value: output.value,
                        key_hash20: output.key_hash20,
                        created_height: height,
                        is_coinbase,
                    },
                );
            }
        }
    }

    let mut balances = watched
        .iter()
        .map(|key| RescanBalance {
            account: key.account,
            index: key.index,
            key_hash20: key.key_hash20,
            unspent_count: 0,
            total: 0,
            spendable: 0,
            immature: 0,
        })
        .collect::<Vec<_>>();
    let mut balance_idx_by_key = HashMap::<(u32, u32, [u8; 20]), usize>::new();
    for (idx, balance) in balances.iter().enumerate() {
        balance_idx_by_key.insert((balance.account, balance.index, balance.key_hash20), idx);
    }

    let mut unspent_vec = unspent.into_values().collect::<Vec<_>>();
    unspent_vec.sort_by(|a, b| {
        a.created_height
            .cmp(&b.created_height)
            .then(a.outpoint.txid.cmp(&b.outpoint.txid))
            .then(a.outpoint.vout.cmp(&b.outpoint.vout))
    });

    for utxo in &unspent_vec {
        let balance_key = (utxo.account, utxo.index, utxo.key_hash20);
        if let Some(idx) = balance_idx_by_key.get(&balance_key).copied() {
            let balance = &mut balances[idx];
            balance.unspent_count = balance.unspent_count.saturating_add(1);
            balance.total = balance.total.saturating_add(utxo.value as u128);

            let is_immature_coinbase = utxo.is_coinbase
                && tip_height < utxo.created_height.saturating_add(coinbase_maturity);
            if is_immature_coinbase {
                balance.immature = balance.immature.saturating_add(utxo.value as u128);
            } else {
                balance.spendable = balance.spendable.saturating_add(utxo.value as u128);
            }
        }
    }
    balances.sort_by(|a, b| a.account.cmp(&b.account).then(a.index.cmp(&b.index)));

    let unspent_total = balances.iter().map(|b| b.total).sum::<u128>();
    let spendable_total = balances.iter().map(|b| b.spendable).sum::<u128>();
    let immature_total = balances.iter().map(|b| b.immature).sum::<u128>();

    RescanReport {
        scanned_blocks,
        tip_height,
        watched_keys: watched.len(),
        total_received,
        total_spent,
        unspent_total,
        spendable_total,
        immature_total,
        unspent_count: unspent_vec.len(),
        balances,
        unspent: unspent_vec,
    }
}

#[derive(Debug, Error)]
pub enum RescanError {
    #[error("invalid index range: start={start_index}, end={end_index}")]
    InvalidRange { start_index: u32, end_index: u32 },
    #[error("key derivation failed: {0}")]
    Derive(#[from] DeriveKeyError),
    #[error("address generation failed: {0}")]
    Address(#[from] AddressError),
}

#[cfg(test)]
mod tests {
    use super::{derive_watched_keys, rescan_blocks};
    use scam_core::{Block, BlockHeader, Hash256, OutPoint, Target, Transaction, TxIn, TxOut};

    fn make_block(prev: Hash256, timestamp: u64, txs: Vec<Transaction>) -> Block {
        let txids: Vec<Hash256> = txs.iter().map(Transaction::txid).collect();
        let merkle_root = scam_core::merkle::merkle_root(&txids);
        Block {
            header: BlockHeader {
                version: 1,
                prev_block: prev,
                merkle_root,
                timestamp,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: txs,
        }
    }

    fn coinbase_to(value: u64, key_hash20: [u8; 20]) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"coinbase".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut { value, key_hash20 }],
            lock_time: 0,
        }
    }

    #[test]
    fn derive_watched_keys_rejects_invalid_range() {
        let seed = [1u8; 64];
        let err = derive_watched_keys(&seed, 0, 5, 4).expect_err("must reject range");
        assert!(matches!(err, super::RescanError::InvalidRange { .. }));
    }

    #[test]
    fn rescan_reports_received_spent_and_unspent() {
        let seed = [2u8; 64];
        let watched = derive_watched_keys(&seed, 0, 0, 0).expect("watch");
        let mine_hash = watched[0].key_hash20;
        let other_hash = [7u8; 20];

        let genesis_coinbase = coinbase_to(50, mine_hash);
        let genesis = make_block(Hash256::ZERO, 100, vec![genesis_coinbase.clone()]);

        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: genesis_coinbase.txid(),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: watched[0].pubkey_compressed.to_vec(),
                sequence: 0,
            }],
            outputs: vec![
                TxOut {
                    value: 30,
                    key_hash20: mine_hash,
                },
                TxOut {
                    value: 19,
                    key_hash20: other_hash,
                },
            ],
            lock_time: 0,
        };
        let block1 = make_block(
            genesis.header.block_hash(),
            220,
            vec![coinbase_to(50, other_hash), spend],
        );

        let report = rescan_blocks(&watched, vec![(0, &genesis), (1, &block1)], 100);
        assert_eq!(report.scanned_blocks, 2);
        assert_eq!(report.tip_height, 1);
        assert_eq!(report.total_received, 80);
        assert_eq!(report.total_spent, 50);
        assert_eq!(report.unspent_total, 30);
        assert_eq!(report.spendable_total, 30);
        assert_eq!(report.immature_total, 0);
        assert_eq!(report.unspent_count, 1);
        assert_eq!(report.balances.len(), 1);
        assert_eq!(report.balances[0].total, 30);
    }

    #[test]
    fn rescan_marks_coinbase_as_immature() {
        let seed = [3u8; 64];
        let watched = derive_watched_keys(&seed, 0, 0, 0).expect("watch");
        let mine_hash = watched[0].key_hash20;
        let genesis = make_block(Hash256::ZERO, 100, vec![coinbase_to(50, mine_hash)]);

        let report = rescan_blocks(&watched, vec![(0, &genesis)], 100);
        assert_eq!(report.unspent_total, 50);
        assert_eq!(report.spendable_total, 0);
        assert_eq!(report.immature_total, 50);
        assert_eq!(report.balances[0].immature, 50);
    }
}
