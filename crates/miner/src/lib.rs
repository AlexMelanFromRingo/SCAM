#![cfg_attr(not(test), deny(clippy::unwrap_used))]
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

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
    /// Height of the block being built (committed to in the coinbase).
    pub height: u64,
    pub prev_block: Hash256,
    pub timestamp: u64,
    pub target: Target,
    pub block_subsidy: u64,
    pub miner_key_hash20: [u8; 20],
    pub coinbase_tag: String,
    pub max_txs: usize,
    /// Budget for the serialized size of the non-coinbase transactions
    /// (as measured by `Transaction::encode_for_hash`). Callers derive it
    /// from the consensus `max_block_size` minus header/coinbase overhead.
    pub max_total_tx_bytes: usize,
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
    let included = select_by_ancestor_feerate(mempool, params.max_txs, params.max_total_tx_bytes);

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
        params.height,
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

struct Candidate {
    fee: u64,
    size: usize,
    /// In-mempool parents only.
    parents: Vec<Hash256>,
    children: Vec<Hash256>,
}

/// Fee and size of a tx together with all its not-yet-selected in-mempool
/// ancestors ("ancestor package").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageScore {
    fee: u128,
    size: u128,
}

impl PackageScore {
    /// Compare by feerate (cross-multiplied, exact), then by absolute fee.
    fn cmp_rate(&self, other: &Self) -> Ordering {
        (self.fee * other.size.max(1))
            .cmp(&(other.fee * self.size.max(1)))
            .then(self.fee.cmp(&other.fee))
    }
}

#[derive(Eq, PartialEq)]
struct HeapEntry {
    score: PackageScore,
    txid: Hash256,
    version: u64,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .cmp_rate(&other.score)
            // Deterministic tie-break: lower txid first.
            .then_with(|| other.txid.cmp(&self.txid))
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Greedy selection by ancestor-package feerate (the Bitcoin Core
/// `BlockAssembler` approach): repeatedly take the transaction whose
/// package — itself plus its unselected in-mempool ancestors — pays the
/// best feerate, add the package parents-first, and rescore descendants.
/// This gives CPFP for free and runs in O(N·A·log N) instead of rescanning
/// the whole mempool for every selected package.
fn select_by_ancestor_feerate(
    mempool: &Mempool,
    max_txs: usize,
    max_total_tx_bytes: usize,
) -> Vec<Hash256> {
    let mut selected = Vec::<Hash256>::new();
    if max_txs == 0 {
        return selected;
    }

    let ranked = mempool.txids_by_feerate_desc();
    let mut candidates = HashMap::<Hash256, Candidate>::with_capacity(ranked.len());
    for txid in &ranked {
        let Some((tx, fee)) = mempool.get_with_fee(txid) else {
            continue;
        };
        let mut parents = Vec::new();
        for input in &tx.inputs {
            let parent = input.prev_out.txid;
            if !input.prev_out.is_coinbase()
                && parent != *txid
                && mempool.contains(&parent)
                && !parents.contains(&parent)
            {
                parents.push(parent);
            }
        }
        candidates.insert(
            *txid,
            Candidate {
                fee,
                size: tx.encode_for_hash().len(),
                parents,
                children: Vec::new(),
            },
        );
    }
    let edges = candidates
        .iter()
        .flat_map(|(txid, c)| c.parents.iter().map(move |parent| (*parent, *txid)))
        .collect::<Vec<_>>();
    for (parent, child) in edges {
        if let Some(entry) = candidates.get_mut(&parent) {
            entry.children.push(child);
        }
    }

    let mut selected_set = HashSet::<Hash256>::new();
    // Txs that can never be selected (package too large for the remaining
    // budget, or part of a dependency cycle).
    let mut skipped = HashSet::<Hash256>::new();
    let mut versions = HashMap::<Hash256, u64>::new();
    let mut heap = BinaryHeap::<HeapEntry>::new();
    for txid in candidates.keys() {
        if let Some((score, _)) = ancestor_package(*txid, &candidates, &selected_set) {
            heap.push(HeapEntry {
                score,
                txid: *txid,
                version: 0,
            });
        }
    }

    let mut used_bytes = 0usize;
    while let Some(entry) = heap.pop() {
        if selected.len() >= max_txs {
            break;
        }
        if selected_set.contains(&entry.txid)
            || skipped.contains(&entry.txid)
            || versions.get(&entry.txid).copied().unwrap_or(0) != entry.version
        {
            continue;
        }
        let Some((score, package)) = ancestor_package(entry.txid, &candidates, &selected_set)
        else {
            skipped.insert(entry.txid);
            continue;
        };
        let package_bytes = usize::try_from(score.size).unwrap_or(usize::MAX);
        if package.len() > max_txs - selected.len()
            || used_bytes.saturating_add(package_bytes) > max_total_tx_bytes
        {
            skipped.insert(entry.txid);
            continue;
        }

        used_bytes += package_bytes;
        let mut touched = Vec::new();
        for txid in &package {
            selected_set.insert(*txid);
            selected.push(*txid);
            if let Some(candidate) = candidates.get(txid) {
                touched.extend(candidate.children.iter().copied());
            }
        }

        // Every unselected descendant of the new package now has a smaller
        // ancestor set: rescore it.
        let mut stack = touched;
        let mut seen = HashSet::<Hash256>::new();
        while let Some(txid) = stack.pop() {
            if selected_set.contains(&txid) || !seen.insert(txid) {
                continue;
            }
            if let Some(candidate) = candidates.get(&txid) {
                stack.extend(candidate.children.iter().copied());
            }
            if skipped.contains(&txid) {
                // A smaller package might fit now.
                skipped.remove(&txid);
            }
            if let Some((score, _)) = ancestor_package(txid, &candidates, &selected_set) {
                let version = versions.entry(txid).or_insert(0);
                *version += 1;
                heap.push(HeapEntry {
                    score,
                    txid,
                    version: *version,
                });
            }
        }
    }
    selected
}

/// Unselected ancestors of `txid` plus `txid`, parents first, with the
/// package's total fee and size. `None` if a dependency cycle is found.
fn ancestor_package(
    txid: Hash256,
    candidates: &HashMap<Hash256, Candidate>,
    selected: &HashSet<Hash256>,
) -> Option<(PackageScore, Vec<Hash256>)> {
    // Iterative post-order DFS so parents are emitted before children.
    let mut ordered = Vec::<Hash256>::new();
    let mut done = HashSet::<Hash256>::new();
    let mut on_path = HashSet::<Hash256>::new();
    let mut stack = vec![(txid, false)];
    while let Some((current, expanded)) = stack.pop() {
        if expanded {
            on_path.remove(&current);
            if done.insert(current) {
                ordered.push(current);
            }
            continue;
        }
        if done.contains(&current) || selected.contains(&current) {
            continue;
        }
        if !on_path.insert(current) {
            return None;
        }
        stack.push((current, true));
        let candidate = candidates.get(&current)?;
        for parent in &candidate.parents {
            if !selected.contains(parent) && !done.contains(parent) {
                if on_path.contains(parent) {
                    return None;
                }
                stack.push((*parent, false));
            }
        }
    }

    let mut score = PackageScore { fee: 0, size: 0 };
    for member in &ordered {
        let candidate = candidates.get(member)?;
        score.fee += u128::from(candidate.fee);
        score.size += candidate.size as u128;
    }
    Some((score, ordered))
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

fn build_coinbase_tx(height: u64, tag: &str, value: u64, key_hash20: [u8; 20]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::coinbase(),
            signature: scam_core::coinbase_script(height, tag.as_bytes()),
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
            height: 1,
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 100,
            miner_key_hash20: [9u8; 20],
            coinbase_tag: "miner-template".to_owned(),
            max_txs: 100,
            max_total_tx_bytes: usize::MAX,
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
            height: 1,
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 100,
            miner_key_hash20: [9u8; 20],
            coinbase_tag: "zero-max-txs".to_owned(),
            max_txs: 0,
            max_total_tx_bytes: usize::MAX,
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
            height: 1,
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [1u8; 20],
            coinbase_tag: "dep-order".to_owned(),
            max_txs: 100,
            max_total_tx_bytes: usize::MAX,
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
            height: 1,
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [3u8; 20],
            coinbase_tag: "cpfp".to_owned(),
            max_txs: 2,
            max_total_tx_bytes: usize::MAX,
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
            height: 1,
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [8u8; 20],
            coinbase_tag: "cpfp-pressure".to_owned(),
            max_txs: 3,
            max_total_tx_bytes: usize::MAX,
        };
        let (_template, summary) =
            build_template_from_mempool(&params, &mempool).expect("template");

        assert_eq!(summary.included_txids.len(), 3);
        assert!(summary.included_txids.contains(&parent_id));
        assert!(summary.included_txids.contains(&child_id));
        assert!(summary.included_txids.contains(&mid_a_id));
    }

    fn params(max_txs: usize, max_total_tx_bytes: usize) -> MempoolTemplateParams {
        MempoolTemplateParams {
            height: 1,
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [4u8; 20],
            coinbase_tag: "budget".to_owned(),
            max_txs,
            max_total_tx_bytes,
        }
    }

    /// M4: the template must respect a byte budget, not only a tx count.
    #[test]
    fn template_builder_respects_byte_budget() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let mut ids = Vec::new();
        for i in 0..10u8 {
            let tx = spend_tx([100 + i; 32], 0, b"budget-tx", 100 + i);
            ids.push(tx.txid());
            mempool
                .insert_with_fee(tx, 10 + u64::from(i))
                .expect("insert");
        }
        let one = spend_tx([100u8; 32], 0, b"budget-tx", 100)
            .encode_for_hash()
            .len();
        let (template, summary) =
            build_template_from_mempool(&params(100, one * 3 + one / 2), &mempool)
                .expect("template");
        assert_eq!(summary.included_txids.len(), 3);
        let bytes: usize = template.transactions[1..]
            .iter()
            .map(|tx| tx.encode_for_hash().len())
            .sum();
        assert!(bytes <= one * 3 + one / 2);
        // Highest fee first.
        assert_eq!(summary.included_txids[0], ids[9]);
    }

    /// A long chain is selected parents-first and a package that no longer
    /// fits is skipped while smaller ones still fill the block.
    #[test]
    fn template_builder_selects_chain_in_dependency_order() {
        let mut mempool = Mempool::with_policy(100, 0).expect("mempool");
        let mut prev = [77u8; 32];
        let mut chain = Vec::new();
        for i in 0..6u8 {
            let tx = spend_tx(prev, 0, b"chain-link", 30 + i);
            prev = tx.txid().0;
            chain.push(tx.txid());
            mempool.insert_with_fee(tx, 5).expect("insert link");
        }
        let (_t, summary) =
            build_template_from_mempool(&params(100, usize::MAX), &mempool).expect("template");
        assert_eq!(summary.included_txids, chain);

        let (_t, limited) =
            build_template_from_mempool(&params(4, usize::MAX), &mempool).expect("template");
        assert_eq!(limited.included_txids, chain[..4].to_vec());
    }

    /// Thousands of independent txs must not take quadratic-or-worse time
    /// (the old package scan was O(N^3)). Run as a smoke test.
    #[test]
    fn template_builder_handles_large_mempool() {
        let mut mempool = Mempool::with_policy(20_000, 0).expect("mempool");
        for i in 0..5_000u32 {
            let mut prev = [0u8; 32];
            prev[..4].copy_from_slice(&i.to_le_bytes());
            let tx = spend_tx(prev, 0, b"bulk", (i % 251) as u8);
            mempool
                .insert_with_fee(tx, 1 + u64::from(i % 97))
                .expect("insert bulk");
        }
        let (_t, summary) =
            build_template_from_mempool(&params(4_000, usize::MAX), &mempool).expect("template");
        assert_eq!(summary.included_txids.len(), 4_000);
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
            height: 1,
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [5u8; 20],
            coinbase_tag: "mgr".to_owned(),
            max_txs: 100,
            max_total_tx_bytes: usize::MAX,
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
            height: 1,
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            block_subsidy: 50,
            miner_key_hash20: [7u8; 20],
            coinbase_tag: "invalidate".to_owned(),
            max_txs: 100,
            max_total_tx_bytes: usize::MAX,
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
