use std::collections::{HashMap, HashSet};

use scam_core::{
    Block, BlockHeader, Hash256, OutPoint, Target, Transaction, TxIn, TxOut, header_meets_pow,
};
use scam_mempool::Mempool;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TemplateRefresh {
    Rebuilt,
    Cached,
}

#[derive(Default)]
pub struct TemplateManager {
    cached: Option<CachedTemplate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedTemplate {
    tip_hash: Hash256,
    mempool_revision: u64,
    template: BlockTemplate,
    summary: TemplateBuildSummary,
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
    let mut entries = HashMap::<Hash256, CandidateEntry>::new();
    for txid in &ranked {
        let Some((tx, fee)) = mempool.get_with_fee(txid) else {
            continue;
        };
        let parents = tx
            .inputs
            .iter()
            .filter_map(|input| {
                if input.prev_out.is_coinbase() {
                    return None;
                }
                let parent = input.prev_out.txid;
                mempool.contains(&parent).then_some(parent)
            })
            .collect::<Vec<_>>();
        entries.insert(
            *txid,
            CandidateEntry {
                fee,
                size: tx.encode_for_hash().len(),
                parents,
            },
        );
    }

    let mut children = HashMap::<Hash256, Vec<Hash256>>::new();
    for (txid, entry) in &entries {
        for parent in &entry.parents {
            children.entry(*parent).or_default().push(*txid);
        }
    }

    let mut included = Vec::<Hash256>::new();
    let mut included_set = HashSet::<Hash256>::new();

    loop {
        if included.len() >= params.max_txs {
            break;
        }
        let ready_roots = ranked
            .iter()
            .copied()
            .filter(|txid| {
                if included_set.contains(txid) {
                    return false;
                }
                entries
                    .get(txid)
                    .map(|entry| {
                        entry
                            .parents
                            .iter()
                            .all(|parent| included_set.contains(parent))
                    })
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if ready_roots.is_empty() {
            break;
        }

        let mut best: Option<PackageCandidate> = None;
        for root in ready_roots {
            let package = build_cpfp_package(
                root,
                &ranked,
                &entries,
                &children,
                &included_set,
                params.max_txs.saturating_sub(included.len()),
            );
            if package.ordered_txids.is_empty() {
                continue;
            }
            match &best {
                Some(current) => {
                    if package_beats_current(&package, current) {
                        best = Some(package);
                    }
                }
                None => best = Some(package),
            }
        }

        let Some(best_package) = best else {
            break;
        };
        for txid in best_package.ordered_txids {
            if included_set.insert(txid) {
                included.push(txid);
            }
        }
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

#[derive(Clone)]
struct CandidateEntry {
    fee: u64,
    size: usize,
    parents: Vec<Hash256>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageCandidate {
    root: Hash256,
    ordered_txids: Vec<Hash256>,
    total_fee: u64,
    total_size: usize,
    score_key: u128,
}

fn build_cpfp_package(
    root: Hash256,
    ranked: &[Hash256],
    entries: &HashMap<Hash256, CandidateEntry>,
    children: &HashMap<Hash256, Vec<Hash256>>,
    included_set: &HashSet<Hash256>,
    max_package_txs: usize,
) -> PackageCandidate {
    if max_package_txs == 0 {
        return PackageCandidate {
            root,
            ordered_txids: Vec::new(),
            total_fee: 0,
            total_size: 0,
            score_key: 0,
        };
    }

    let mut package = HashSet::<Hash256>::new();
    package.insert(root);

    // Safety bound: package membership is monotonic and cannot grow beyond candidate count.
    for _ in 0..=entries.len() {
        let mut changed = false;
        let current = package.iter().copied().collect::<Vec<_>>();
        for txid in current {
            let Some(descendants) = children.get(&txid) else {
                continue;
            };
            for child in descendants {
                if included_set.contains(child) {
                    continue;
                }
                let Some(entry) = entries.get(child) else {
                    continue;
                };
                let all_parents_ready = entry
                    .parents
                    .iter()
                    .all(|parent| included_set.contains(parent) || package.contains(parent));
                if all_parents_ready {
                    changed |= package.insert(*child);
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut remaining = package.clone();
    let mut ordered = Vec::<Hash256>::new();
    let mut total_fee = 0u64;
    let mut total_size = 0usize;
    let package_limit = package.len().min(max_package_txs);

    // Safety bound: each pass must either order at least one txid or terminate.
    for _ in 0..=entries.len() {
        if remaining.is_empty() {
            break;
        }
        if ordered.len() == package_limit {
            break;
        }
        debug_assert!(ordered.len() < package_limit);
        let mut progressed = false;
        let ready_ranked = ranked
            .iter()
            .copied()
            .filter(|txid| remaining.contains(txid))
            .collect::<Vec<_>>();
        for txid in ready_ranked {
            if ordered.len() == package_limit {
                break;
            }
            let Some(entry) = entries.get(&txid) else {
                continue;
            };
            let parents_ready = entry
                .parents
                .iter()
                .all(|parent| included_set.contains(parent) || !remaining.contains(parent));
            if !parents_ready {
                continue;
            }
            remaining.remove(&txid);
            ordered.push(txid);
            total_fee = total_fee.saturating_add(entry.fee);
            total_size = total_size.saturating_add(entry.size);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    let score_key = if total_size == 0 {
        0
    } else {
        ((total_fee as u128) * 1000) / (total_size as u128)
    };
    PackageCandidate {
        root,
        ordered_txids: ordered,
        total_fee,
        total_size,
        score_key,
    }
}

fn package_beats_current(candidate: &PackageCandidate, current: &PackageCandidate) -> bool {
    let candidate_rank = (
        candidate.score_key,
        candidate.total_fee,
        std::cmp::Reverse(candidate.root),
    );
    let current_rank = (
        current.score_key,
        current.total_fee,
        std::cmp::Reverse(current.root),
    );
    candidate_rank.cmp(&current_rank).is_gt()
}

impl TemplateManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build_or_reuse(
        &mut self,
        params: &MempoolTemplateParams,
        mempool: &Mempool,
    ) -> Result<(TemplateRefresh, BlockTemplate, TemplateBuildSummary), MinerError> {
        let tip_hash = params.prev_block;
        let mempool_revision = mempool.revision();
        if let Some(cached) = &self.cached
            && cached.tip_hash == tip_hash
            && cached.mempool_revision == mempool_revision
        {
            return Ok((
                TemplateRefresh::Cached,
                cached.template.clone(),
                cached.summary.clone(),
            ));
        }

        let (template, summary) = build_template_from_mempool(params, mempool)?;
        self.cached = Some(CachedTemplate {
            tip_hash,
            mempool_revision,
            template: template.clone(),
            summary: summary.clone(),
        });
        Ok((TemplateRefresh::Rebuilt, template, summary))
    }

    pub fn invalidate(&mut self) {
        self.cached = None;
    }
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
    use std::collections::{HashMap, HashSet};

    use scam_core::{OutPoint, Target, Transaction, TxIn, TxOut};
    use scam_mempool::Mempool;

    use super::{CandidateEntry, PackageCandidate, build_cpfp_package, package_beats_current};
    use crate::{
        BlockTemplate, MempoolTemplateParams, TemplateManager, TemplateRefresh,
        build_template_from_mempool, mine_block, mine_block_with_extra_nonce,
        template_with_extra_nonce,
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
    fn template_builder_respects_zero_max_txs() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let tx_a = spend_tx([61u8; 32], 0, b"zero-limit-a", 1);
        let tx_b = spend_tx([62u8; 32], 0, b"zero-limit-b", 2);
        mempool.insert_with_fee(tx_a, 10).expect("insert a");
        mempool.insert_with_fee(tx_b, 50).expect("insert b");

        let params = MempoolTemplateParams {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 100,
            miner_key_hash20: [9u8; 20],
            coinbase_tag: "zero-max-txs".to_owned(),
            max_txs: 0,
        };
        let (template, summary) = build_template_from_mempool(&params, &mempool).expect("template");
        assert!(summary.included_txids.is_empty());
        assert_eq!(summary.total_fees, 0);
        assert_eq!(template.transactions.len(), 1);
        assert_eq!(template.transactions[0].outputs[0].value, 100);
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
    fn template_builder_applies_cpfp_package_selection() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let parent = spend_tx([10u8; 32], 0, b"cpfp-parent", 10);
        let parent_id = parent.txid();
        let child = spend_tx(parent_id.0, 0, b"cpfp-child", 11);
        let child_id = child.txid();
        let unrelated = spend_tx([12u8; 32], 0, b"unrelated", 12);
        let unrelated_id = unrelated.txid();

        mempool.insert_with_fee(parent, 1).expect("insert parent");
        mempool.insert_with_fee(child, 1_000).expect("insert child");
        mempool
            .insert_with_fee(unrelated, 100)
            .expect("insert unrelated");

        let params = MempoolTemplateParams {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [3u8; 20],
            coinbase_tag: "cpfp".to_owned(),
            max_txs: 2,
        };
        let (_template, summary) =
            build_template_from_mempool(&params, &mempool).expect("template");
        assert_eq!(summary.included_txids, vec![parent_id, child_id]);
        assert!(!summary.included_txids.contains(&unrelated_id));
    }

    #[test]
    fn template_builder_keeps_cpfp_package_under_fee_pressure() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let parent = spend_tx([21u8; 32], 0, b"parent-low", 21);
        let parent_id = parent.txid();
        let child = spend_tx(parent_id.0, 0, b"child-high", 22);
        let child_id = child.txid();
        let mid_a = spend_tx([23u8; 32], 0, b"mid-a", 23);
        let mid_a_id = mid_a.txid();
        let mid_b = spend_tx([24u8; 32], 0, b"mid-b", 24);
        let mid_c = spend_tx([25u8; 32], 0, b"mid-c", 25);

        mempool.insert_with_fee(parent, 1).expect("insert parent");
        mempool.insert_with_fee(child, 1_000).expect("insert child");
        mempool.insert_with_fee(mid_a, 400).expect("insert mid_a");
        mempool.insert_with_fee(mid_b, 350).expect("insert mid_b");
        mempool.insert_with_fee(mid_c, 300).expect("insert mid_c");

        let params = MempoolTemplateParams {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [8u8; 20],
            coinbase_tag: "cpfp-pressure".to_owned(),
            max_txs: 3,
        };
        let (_template, summary) =
            build_template_from_mempool(&params, &mempool).expect("template");

        assert_eq!(summary.included_txids.len(), 3);
        assert!(summary.included_txids.contains(&parent_id));
        assert!(summary.included_txids.contains(&child_id));
        assert!(summary.included_txids.contains(&mid_a_id));
    }

    #[test]
    fn cpfp_package_builder_terminates_on_cyclic_dependencies() {
        let a = scam_core::Hash256([1u8; 32]);
        let b = scam_core::Hash256([2u8; 32]);

        let ranked = vec![a, b];
        let mut entries = HashMap::<scam_core::Hash256, CandidateEntry>::new();
        entries.insert(
            a,
            CandidateEntry {
                fee: 10,
                size: 100,
                parents: vec![b],
            },
        );
        entries.insert(
            b,
            CandidateEntry {
                fee: 10,
                size: 100,
                parents: vec![a],
            },
        );

        let mut children = HashMap::<scam_core::Hash256, Vec<scam_core::Hash256>>::new();
        children.insert(a, vec![b]);
        children.insert(b, vec![a]);
        let included = HashSet::new();

        let package = build_cpfp_package(a, &ranked, &entries, &children, &included, 8);
        assert!(package.ordered_txids.is_empty());
        assert_eq!(package.total_fee, 0);
        assert_eq!(package.total_size, 0);
        assert_eq!(package.score_key, 0);
    }

    #[test]
    fn cpfp_package_builder_orders_dependencies_before_descendants() {
        let root = scam_core::Hash256([11u8; 32]);
        let c1 = scam_core::Hash256([12u8; 32]);
        let c2 = scam_core::Hash256([13u8; 32]);
        let c3 = scam_core::Hash256([14u8; 32]);

        let ranked = vec![c3, c2, c1, root];
        let mut entries = HashMap::<scam_core::Hash256, CandidateEntry>::new();
        entries.insert(
            root,
            CandidateEntry {
                fee: 1,
                size: 100,
                parents: vec![],
            },
        );
        entries.insert(
            c1,
            CandidateEntry {
                fee: 2,
                size: 100,
                parents: vec![root],
            },
        );
        entries.insert(
            c2,
            CandidateEntry {
                fee: 3,
                size: 100,
                parents: vec![c1],
            },
        );
        entries.insert(
            c3,
            CandidateEntry {
                fee: 4,
                size: 100,
                parents: vec![c2],
            },
        );

        let mut children = HashMap::<scam_core::Hash256, Vec<scam_core::Hash256>>::new();
        children.insert(root, vec![c1]);
        children.insert(c1, vec![c2]);
        children.insert(c2, vec![c3]);
        let included = HashSet::new();

        let package = build_cpfp_package(root, &ranked, &entries, &children, &included, 8);
        assert_eq!(package.ordered_txids, vec![root, c1, c2, c3]);
        assert_eq!(package.total_fee, 10);
        assert_eq!(package.total_size, 400);
        assert_eq!(package.score_key, 25);
    }

    #[test]
    fn cpfp_package_builder_respects_zero_tx_limit() {
        let root = scam_core::Hash256([31u8; 32]);
        let ranked = vec![root];
        let mut entries = HashMap::<scam_core::Hash256, CandidateEntry>::new();
        entries.insert(
            root,
            CandidateEntry {
                fee: 100,
                size: 200,
                parents: vec![],
            },
        );
        let children = HashMap::<scam_core::Hash256, Vec<scam_core::Hash256>>::new();
        let included = HashSet::new();

        let package = build_cpfp_package(root, &ranked, &entries, &children, &included, 0);
        assert_eq!(package.ordered_txids, Vec::<scam_core::Hash256>::new());
        assert_eq!(package.total_fee, 0);
        assert_eq!(package.total_size, 0);
        assert_eq!(package.score_key, 0);
    }

    #[test]
    fn cpfp_package_builder_ignores_ranked_entries_outside_package() {
        let root = scam_core::Hash256([41u8; 32]);
        let child = scam_core::Hash256([42u8; 32]);
        let outsider_a = scam_core::Hash256([90u8; 32]);
        let outsider_b = scam_core::Hash256([91u8; 32]);

        let ranked = vec![outsider_a, outsider_b, child, root];
        let mut entries = HashMap::<scam_core::Hash256, CandidateEntry>::new();
        entries.insert(
            root,
            CandidateEntry {
                fee: 1,
                size: 100,
                parents: vec![],
            },
        );
        entries.insert(
            child,
            CandidateEntry {
                fee: 2,
                size: 100,
                parents: vec![root],
            },
        );
        entries.insert(
            outsider_a,
            CandidateEntry {
                fee: 999,
                size: 100,
                parents: vec![],
            },
        );
        entries.insert(
            outsider_b,
            CandidateEntry {
                fee: 888,
                size: 100,
                parents: vec![],
            },
        );

        let mut children = HashMap::<scam_core::Hash256, Vec<scam_core::Hash256>>::new();
        children.insert(root, vec![child]);
        let included = HashSet::new();

        let package = build_cpfp_package(root, &ranked, &entries, &children, &included, 2);
        assert_eq!(package.ordered_txids, vec![root, child]);
    }

    #[test]
    fn cpfp_package_builder_enforces_strict_package_limit() {
        let root = scam_core::Hash256([51u8; 32]);
        let child_a = scam_core::Hash256([52u8; 32]);
        let child_b = scam_core::Hash256([53u8; 32]);
        let child_c = scam_core::Hash256([54u8; 32]);

        let ranked = vec![child_c, child_b, child_a, root];
        let mut entries = HashMap::<scam_core::Hash256, CandidateEntry>::new();
        entries.insert(
            root,
            CandidateEntry {
                fee: 1,
                size: 100,
                parents: vec![],
            },
        );
        entries.insert(
            child_a,
            CandidateEntry {
                fee: 2,
                size: 100,
                parents: vec![root],
            },
        );
        entries.insert(
            child_b,
            CandidateEntry {
                fee: 3,
                size: 100,
                parents: vec![child_a],
            },
        );
        entries.insert(
            child_c,
            CandidateEntry {
                fee: 4,
                size: 100,
                parents: vec![child_b],
            },
        );

        let mut children = HashMap::<scam_core::Hash256, Vec<scam_core::Hash256>>::new();
        children.insert(root, vec![child_a]);
        children.insert(child_a, vec![child_b]);
        children.insert(child_b, vec![child_c]);
        let included = HashSet::new();

        let package = build_cpfp_package(root, &ranked, &entries, &children, &included, 2);
        assert_eq!(package.ordered_txids, vec![root, child_a]);
        assert_eq!(package.total_fee, 3);
        assert_eq!(package.total_size, 200);
        assert_eq!(package.score_key, 15);
    }

    #[test]
    fn package_comparator_uses_score_fee_and_root_tiebreak() {
        let base = PackageCandidate {
            root: scam_core::Hash256([10u8; 32]),
            ordered_txids: vec![],
            total_fee: 100,
            total_size: 200,
            score_key: 500,
        };

        let higher_score = PackageCandidate {
            root: scam_core::Hash256([11u8; 32]),
            ordered_txids: vec![],
            total_fee: 1,
            total_size: 1,
            score_key: 501,
        };
        assert!(package_beats_current(&higher_score, &base));

        let same_score_higher_fee = PackageCandidate {
            root: scam_core::Hash256([12u8; 32]),
            ordered_txids: vec![],
            total_fee: 101,
            total_size: 200,
            score_key: 500,
        };
        assert!(package_beats_current(&same_score_higher_fee, &base));

        let same_score_fee_lower_root = PackageCandidate {
            root: scam_core::Hash256([9u8; 32]),
            ordered_txids: vec![],
            total_fee: 100,
            total_size: 200,
            score_key: 500,
        };
        assert!(package_beats_current(&same_score_fee_lower_root, &base));

        let same_score_fee_higher_root = PackageCandidate {
            root: scam_core::Hash256([20u8; 32]),
            ordered_txids: vec![],
            total_fee: 100,
            total_size: 200,
            score_key: 500,
        };
        assert!(!package_beats_current(&same_score_fee_higher_root, &base));
    }

    #[test]
    fn package_comparator_rejects_exact_ties() {
        let base = PackageCandidate {
            root: scam_core::Hash256([77u8; 32]),
            ordered_txids: vec![],
            total_fee: 100,
            total_size: 200,
            score_key: 500,
        };
        assert!(!package_beats_current(&base, &base));
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

    #[test]
    fn template_manager_rebuilds_on_tip_or_mempool_change() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let tx_low = spend_tx([31u8; 32], 0, b"same-size-a", 1);
        let tx_high = spend_tx([32u8; 32], 0, b"same-size-b", 2);
        mempool.insert_with_fee(tx_low, 10).expect("insert low");

        let mut manager = TemplateManager::new();
        let params = MempoolTemplateParams {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [5u8; 20],
            coinbase_tag: "mgr".to_owned(),
            max_txs: 100,
        };

        let (refresh_a, _template_a, summary_a) = manager
            .build_or_reuse(&params, &mempool)
            .expect("first build");
        assert_eq!(refresh_a, TemplateRefresh::Rebuilt);
        assert_eq!(summary_a.included_txids.len(), 1);

        let (refresh_b, _template_b, summary_b) = manager
            .build_or_reuse(&params, &mempool)
            .expect("second build");
        assert_eq!(refresh_b, TemplateRefresh::Cached);
        assert_eq!(summary_b.included_txids.len(), 1);

        mempool.insert_with_fee(tx_high, 50).expect("insert high");
        let (refresh_c, _template_c, summary_c) = manager
            .build_or_reuse(&params, &mempool)
            .expect("rebuild on mempool change");
        assert_eq!(refresh_c, TemplateRefresh::Rebuilt);
        assert_eq!(summary_c.included_txids.len(), 2);

        let mut next_tip_params = params.clone();
        next_tip_params.prev_block = scam_core::hash::hash256(b"new-tip");
        let (refresh_d, _template_d, _summary_d) = manager
            .build_or_reuse(&next_tip_params, &mempool)
            .expect("rebuild on tip change");
        assert_eq!(refresh_d, TemplateRefresh::Rebuilt);
    }

    #[test]
    fn template_manager_invalidate_forces_rebuild() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let tx = spend_tx([61u8; 32], 0, b"invalidate", 1);
        mempool.insert_with_fee(tx, 10).expect("insert tx");

        let mut manager = TemplateManager::new();
        let params = MempoolTemplateParams {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [7u8; 20],
            coinbase_tag: "invalidate".to_owned(),
            max_txs: 100,
        };

        let (refresh_a, _, _) = manager.build_or_reuse(&params, &mempool).expect("build");
        assert_eq!(refresh_a, TemplateRefresh::Rebuilt);
        let (refresh_b, _, _) = manager.build_or_reuse(&params, &mempool).expect("cached");
        assert_eq!(refresh_b, TemplateRefresh::Cached);

        manager.invalidate();
        let (refresh_c, _, _) = manager
            .build_or_reuse(&params, &mempool)
            .expect("rebuild after invalidate");
        assert_eq!(refresh_c, TemplateRefresh::Rebuilt);
    }
}
