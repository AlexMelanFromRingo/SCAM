use std::collections::HashSet;

use scam_core::{
    Block, BlockHeader, Hash256, OutPoint, Target, Transaction, TxIn, TxOut, header_meets_pow,
};
use scam_mempool::Mempool;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct BlockTemplate {
    pub version: u32,
    pub prev_block: Hash256,
    pub timestamp: u64,
    pub target: Target,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug)]
pub struct MempoolTemplateParams {
    pub version: u32,
    pub prev_block: Hash256,
    pub timestamp: u64,
    pub target: Target,
    pub block_subsidy: u64,
    pub miner_key_hash20: [u8; 20],
    pub coinbase_tag: String,
    pub max_txs: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateBuildSummary {
    pub included_txids: Vec<Hash256>,
    pub total_fees: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinedBlock {
    pub block: Block,
    pub extra_nonce: u64,
}

impl BlockTemplate {
    pub fn build_with_nonce(&self, nonce: u64) -> Block {
        let txids: Vec<Hash256> = self.transactions.iter().map(Transaction::txid).collect();
        let merkle_root = scam_core::merkle::merkle_root(&txids);
        Block {
            header: BlockHeader {
                version: self.version,
                prev_block: self.prev_block,
                merkle_root,
                timestamp: self.timestamp,
                target: self.target,
                nonce,
            },
            transactions: self.transactions.clone(),
        }
    }
}

pub fn build_template_from_mempool(
    params: &MempoolTemplateParams,
    mempool: &Mempool,
) -> Result<(BlockTemplate, TemplateBuildSummary), MinerError> {
    let ranked = mempool.txids_by_feerate_desc();
    let mut pending = ranked
        .into_iter()
        .take(params.max_txs)
        .collect::<Vec<Hash256>>();
    let candidate_set = pending.iter().copied().collect::<HashSet<Hash256>>();
    let mut included = Vec::<Hash256>::new();
    let mut included_set = HashSet::<Hash256>::new();

    while !pending.is_empty() {
        let mut progressed = false;
        let mut next_pending = Vec::<Hash256>::new();

        for txid in pending {
            let Some((tx, _fee)) = mempool.get_with_fee(&txid) else {
                continue;
            };

            let has_parent_outside_candidates = tx.inputs.iter().any(|input| {
                !input.prev_out.is_coinbase()
                    && mempool.contains(&input.prev_out.txid)
                    && !candidate_set.contains(&input.prev_out.txid)
            });
            if has_parent_outside_candidates {
                continue;
            }

            let has_unmet_parent = tx.inputs.iter().any(|input| {
                !input.prev_out.is_coinbase()
                    && mempool.contains(&input.prev_out.txid)
                    && !included_set.contains(&input.prev_out.txid)
            });
            if has_unmet_parent {
                next_pending.push(txid);
                continue;
            }

            included.push(txid);
            included_set.insert(txid);
            progressed = true;
        }

        if !progressed {
            break;
        }
        pending = next_pending;
    }

    let mut total_fees = 0u64;
    let mut txs = Vec::<Transaction>::with_capacity(1 + included.len());
    for txid in &included {
        let Some((tx, fee)) = mempool.get_with_fee(txid) else {
            continue;
        };
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(MinerError::FeeOverflow { txid: *txid })?;
        txs.push(tx.clone());
    }

    let coinbase_value =
        params
            .block_subsidy
            .checked_add(total_fees)
            .ok_or(MinerError::RewardOverflow {
                subsidy: params.block_subsidy,
                total_fees,
            })?;
    let coinbase = build_coinbase_tx(
        &params.coinbase_tag,
        coinbase_value,
        params.miner_key_hash20,
    );

    let mut transactions = Vec::with_capacity(txs.len() + 1);
    transactions.push(coinbase);
    transactions.extend(txs);

    let template = BlockTemplate {
        version: params.version,
        prev_block: params.prev_block,
        timestamp: params.timestamp,
        target: params.target,
        transactions,
    };
    let summary = TemplateBuildSummary {
        included_txids: included,
        total_fees,
    };
    Ok((template, summary))
}

fn build_coinbase_tx(tag: &str, value: u64, key_hash20: [u8; 20]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::coinbase(),
            signature: tag.as_bytes().to_vec(),
            pubkey_compressed: vec![],
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut { value, key_hash20 }],
        lock_time: 0,
    }
}

fn template_with_extra_nonce(template: &BlockTemplate, extra_nonce: u64) -> BlockTemplate {
    let mut candidate = template.clone();
    if let Some(coinbase) = candidate.transactions.first_mut()
        && coinbase.is_coinbase()
    {
        coinbase.inputs[0]
            .signature
            .extend_from_slice(&extra_nonce.to_le_bytes());
    }
    candidate
}

pub fn mine_block_with_extra_nonce(
    template: &BlockTemplate,
    max_extra_nonce: u64,
    max_nonce: u64,
) -> Option<MinedBlock> {
    for extra_nonce in 0..=max_extra_nonce {
        let candidate_template = template_with_extra_nonce(template, extra_nonce);
        for nonce in 0..=max_nonce {
            let candidate = candidate_template.build_with_nonce(nonce);
            if header_meets_pow(&candidate.header) {
                return Some(MinedBlock {
                    block: candidate,
                    extra_nonce,
                });
            }
        }
    }
    None
}

pub fn mine_block(template: &BlockTemplate, max_nonce: u64) -> Option<Block> {
    mine_block_with_extra_nonce(template, 0, max_nonce).map(|mined| mined.block)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MinerError {
    #[error("fee sum overflow while adding tx {txid}")]
    FeeOverflow { txid: Hash256 },
    #[error("coinbase reward overflow: subsidy={subsidy}, total_fees={total_fees}")]
    RewardOverflow { subsidy: u64, total_fees: u64 },
}

#[cfg(test)]
mod tests {
    use scam_core::{OutPoint, Target, Transaction, TxIn, TxOut};
    use scam_mempool::Mempool;

    use crate::{
        BlockTemplate, MempoolTemplateParams, build_template_from_mempool, mine_block,
        mine_block_with_extra_nonce, template_with_extra_nonce,
    };

    fn coinbase() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"coinbase".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: [0u8; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn max_target_finds_nonce_immediately() {
        let template = BlockTemplate {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            transactions: vec![coinbase()],
        };
        let mined = mine_block(&template, 100).expect("must mine");
        assert_eq!(mined.header.nonce, 0);
    }

    #[test]
    fn tiny_search_space_can_fail() {
        let template = BlockTemplate {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::from_hex(
                "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .expect("target parse"),
            transactions: vec![coinbase()],
        };
        let mined = mine_block(&template, 1);
        if let Some(block) = mined {
            assert!(scam_core::header_meets_pow(&block.header));
        }
    }

    fn spend_tx(prev_txid: [u8; 32], vout: u32, sig: &[u8], out_seed: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: scam_core::Hash256(prev_txid),
                    vout,
                },
                signature: sig.to_vec(),
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 10,
                key_hash20: [out_seed; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn template_builder_uses_feerate_order_and_fee_sum() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let tx_low = spend_tx([1u8; 32], 0, b"same-size-a", 1);
        let tx_high = spend_tx([2u8; 32], 0, b"same-size-b", 2);
        let low_id = tx_low.txid();
        let high_id = tx_high.txid();
        mempool.insert_with_fee(tx_low, 10).expect("insert low");
        mempool.insert_with_fee(tx_high, 50).expect("insert high");

        let params = MempoolTemplateParams {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 100,
            miner_key_hash20: [9u8; 20],
            coinbase_tag: "miner-template".to_owned(),
            max_txs: 100,
        };
        let (template, summary) = build_template_from_mempool(&params, &mempool).expect("template");
        assert_eq!(summary.included_txids, vec![high_id, low_id]);
        assert_eq!(summary.total_fees, 60);
        assert_eq!(template.transactions.len(), 3);
        assert_eq!(template.transactions[0].outputs[0].value, 160);
    }

    #[test]
    fn template_builder_orders_parent_before_child() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let parent = spend_tx([7u8; 32], 0, b"parent", 7);
        let parent_id = parent.txid();
        let child = spend_tx(parent_id.0, 0, b"child-with-higher-fee", 8);
        let child_id = child.txid();
        mempool.insert_with_fee(parent, 1).expect("insert parent");
        mempool.insert_with_fee(child, 100).expect("insert child");

        let params = MempoolTemplateParams {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [1u8; 20],
            coinbase_tag: "dep-order".to_owned(),
            max_txs: 100,
        };
        let (template, summary) = build_template_from_mempool(&params, &mempool).expect("template");
        assert_eq!(summary.included_txids, vec![parent_id, child_id]);
        assert_eq!(summary.total_fees, 101);
        assert_eq!(template.transactions[1].txid(), parent_id);
        assert_eq!(template.transactions[2].txid(), child_id);
    }

    #[test]
    fn extra_nonce_is_injected_into_coinbase_signature() {
        let template = BlockTemplate {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            transactions: vec![coinbase()],
        };
        let mut expected = b"coinbase".to_vec();
        expected.extend_from_slice(&7u64.to_le_bytes());

        let enriched = template_with_extra_nonce(&template, 7);
        assert_eq!(enriched.transactions[0].inputs[0].signature, expected);
    }

    #[test]
    fn mine_block_with_zero_extra_nonce_matches_mine_block() {
        let template = BlockTemplate {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            transactions: vec![coinbase()],
        };
        let legacy = mine_block(&template, 10).expect("legacy mining");
        let mined = mine_block_with_extra_nonce(&template, 0, 10).expect("extra nonce mining");
        assert_eq!(legacy.header.block_hash(), mined.block.header.block_hash());
        assert_eq!(mined.extra_nonce, 0);
    }
}
