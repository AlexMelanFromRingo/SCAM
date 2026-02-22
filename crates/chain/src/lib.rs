use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use num_bigint::BigUint;
use scam_consensus::{
    BlockApplySummary, BlockValidationError, UtxoEntry, UtxoSet, asert_next, chainwork_for_target,
    lwma_next, retarget_next, validate_and_apply_block, validate_block_basic,
};
use scam_core::{Block, BlockHeader, ChainConfig, DifficultyAlgorithm, Hash256, Target};
use thiserror::Error;

const MEDIAN_TIME_PAST_WINDOW: usize = 11;
const MAX_FUTURE_BLOCK_TIME_SEC: u64 = 2 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockSubmissionOutcome {
    AlreadyKnown {
        block_hash: Hash256,
    },
    StoredSideBranch {
        block_hash: Hash256,
    },
    ExtendedTip {
        new_tip: Hash256,
        new_height: u64,
    },
    Reorged {
        old_tip: Hash256,
        new_tip: Hash256,
        new_height: u64,
    },
}

pub struct ChainRuntime {
    config: ChainConfig,
    utxos: UtxoSet,
    blocks: HashMap<Hash256, Block>,
    headers: HashMap<Hash256, BlockHeader>,
    cumulative_work: HashMap<Hash256, BigUint>,
    main_chain: Vec<Hash256>,
    undo_data: HashMap<Hash256, BlockUndo>,
}

#[derive(Clone, Debug)]
struct BlockUndo {
    spent_entries: Vec<(scam_core::OutPoint, UtxoEntry)>,
    created_outpoints: Vec<scam_core::OutPoint>,
}

impl ChainRuntime {
    pub fn from_config(config: ChainConfig) -> Result<Self, ChainError> {
        config.validate()?;
        let genesis = config.build_genesis_block()?;
        Self::new(config, genesis)
    }

    pub fn from_ordered_blocks(
        config: ChainConfig,
        blocks_by_height: Vec<Block>,
    ) -> Result<Self, ChainError> {
        let Some(first) = blocks_by_height.first() else {
            return Err(ChainError::InvalidRuntime(
                "ordered chain blocks cannot be empty".to_owned(),
            ));
        };
        config.validate()?;
        let expected_genesis = config.build_genesis_block()?;
        let expected_hash = expected_genesis.header.block_hash();
        let got_hash = first.header.block_hash();
        if got_hash != expected_hash {
            return Err(ChainError::UnexpectedGenesis {
                expected: expected_hash,
                got: got_hash,
            });
        }

        let mut runtime = Self::new(config, first.clone())?;
        for block in blocks_by_height.into_iter().skip(1) {
            runtime.apply_next_block(block)?;
        }
        Ok(runtime)
    }

    pub fn new(config: ChainConfig, genesis: Block) -> Result<Self, ChainError> {
        let mut utxos = UtxoSet::new();
        let applied = validate_and_apply_block(
            &genesis,
            0,
            config.block_subsidy,
            config.coinbase_maturity as u64,
            config.network_id.as_bytes(),
            &mut utxos,
        )?;

        let genesis_hash = applied.block_hash;
        let genesis_header = genesis.header.clone();
        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis);
        let mut headers = HashMap::new();
        headers.insert(genesis_hash, genesis_header.clone());
        let mut cumulative_work = HashMap::new();
        cumulative_work.insert(genesis_hash, chainwork_for_target(genesis_header.target));

        Ok(Self {
            config,
            utxos,
            blocks,
            headers,
            cumulative_work,
            main_chain: vec![genesis_hash],
            undo_data: HashMap::new(),
        })
    }

    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    pub fn tip_height(&self) -> u64 {
        (self.main_chain.len() - 1) as u64
    }

    pub fn tip_hash(&self) -> Hash256 {
        *self.main_chain.last().expect("chain always has genesis")
    }

    pub fn tip_header(&self) -> &BlockHeader {
        self.headers
            .get(&self.tip_hash())
            .expect("tip header must exist")
    }

    pub fn block_hashes(&self) -> &[Hash256] {
        &self.main_chain
    }

    pub fn block_hash_at_height(&self, height: u64) -> Option<Hash256> {
        self.main_chain.get(height as usize).copied()
    }

    pub fn block_by_hash(&self, hash: &Hash256) -> Option<&Block> {
        self.blocks.get(hash)
    }

    pub fn main_chain_blocks(&self) -> Result<Vec<Block>, ChainError> {
        let mut blocks = Vec::with_capacity(self.main_chain.len());
        for hash in &self.main_chain {
            let block = self
                .blocks
                .get(hash)
                .ok_or(ChainError::MissingBlock { block_hash: *hash })?;
            blocks.push(block.clone());
        }
        Ok(blocks)
    }

    pub fn utxo_set(&self) -> &UtxoSet {
        &self.utxos
    }

    pub fn utxo_len(&self) -> usize {
        self.utxos.len()
    }

    pub fn cumulative_work(&self) -> &BigUint {
        self.cumulative_work
            .get(&self.tip_hash())
            .expect("tip work must exist")
    }

    pub fn header_by_hash(&self, hash: &Hash256) -> Option<&BlockHeader> {
        self.headers.get(hash)
    }

    fn median_time_past(&self, parent_hash: Hash256) -> Result<u64, ChainError> {
        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_PAST_WINDOW);
        let mut cursor = Some(parent_hash);

        for _ in 0..MEDIAN_TIME_PAST_WINDOW {
            let Some(hash) = cursor else {
                break;
            };
            let header = self
                .headers
                .get(&hash)
                .ok_or(ChainError::MissingHeader { block_hash: hash })?;
            timestamps.push(header.timestamp);

            if header.prev_block == Hash256::ZERO {
                break;
            }
            cursor = Some(header.prev_block);
        }

        if timestamps.is_empty() {
            return Err(ChainError::InvalidRuntime(
                "cannot compute median-time-past without headers".to_owned(),
            ));
        }
        timestamps.sort_unstable();
        Ok(timestamps[timestamps.len() / 2])
    }

    fn validate_contextual_timestamps(&self, block: &Block) -> Result<(), ChainError> {
        let block_hash = block.header.block_hash();
        let median_time_past = self.median_time_past(block.header.prev_block)?;
        if block.header.timestamp <= median_time_past {
            return Err(ChainError::TimestampTooOld {
                block_hash,
                median_time_past,
                got: block.header.timestamp,
            });
        }

        let now = current_unix_timestamp()?;
        let max_allowed = now.saturating_add(MAX_FUTURE_BLOCK_TIME_SEC);
        if block.header.timestamp > max_allowed {
            return Err(ChainError::TimestampTooFarInFuture {
                block_hash,
                got: block.header.timestamp,
                max_allowed,
            });
        }

        Ok(())
    }

    pub fn expected_target_for_next_block(&self) -> Result<Target, ChainError> {
        let next_height = self.tip_height() + 1;
        let window = self.config.difficulty_adjustment_window as u64;
        if window == 0 {
            return Err(ChainError::InvalidRuntime(
                "difficulty_adjustment_window must be > 0".to_owned(),
            ));
        }

        let tip_header = self.tip_header();
        let max_target = self.config.genesis_target()?;
        match self.config.difficulty_algorithm {
            DifficultyAlgorithm::Windowed => {
                if !next_height.is_multiple_of(window) {
                    return Ok(tip_header.target);
                }

                let start_height = next_height - window;
                let start_hash = self.main_chain[start_height as usize];
                let start_header = self
                    .headers
                    .get(&start_hash)
                    .expect("header for start height must exist");
                let actual_timespan = tip_header
                    .timestamp
                    .saturating_sub(start_header.timestamp)
                    .max(1);
                let expected_timespan = window * self.config.target_block_time_sec;

                retarget_next(
                    tip_header.target,
                    actual_timespan,
                    expected_timespan,
                    self.config.difficulty_clamp_down,
                    self.config.difficulty_clamp_up,
                    max_target,
                )
                .map_err(ChainError::Difficulty)
            }
            DifficultyAlgorithm::Lwma => {
                let history = self.main_chain.len();
                let window = self.config.difficulty_adjustment_window as usize;
                if history < window + 1 {
                    return Ok(tip_header.target);
                }
                let start = history - (window + 1);
                let mut targets = Vec::with_capacity(window + 1);
                let mut timestamps = Vec::with_capacity(window + 1);
                for height in start..history {
                    let hash = self.main_chain[height];
                    let header = self
                        .headers
                        .get(&hash)
                        .expect("header at chain height must exist");
                    targets.push(header.target);
                    timestamps.push(header.timestamp);
                }

                lwma_next(
                    &targets,
                    &timestamps,
                    self.config.target_block_time_sec,
                    max_target,
                )
                .map_err(ChainError::Difficulty)
            }
            DifficultyAlgorithm::Asert => {
                if self.main_chain.len() < 2 {
                    return Ok(tip_header.target);
                }
                let parent_header = self
                    .headers
                    .get(&tip_header.prev_block)
                    .expect("parent header for tip must exist");
                let observed = tip_header
                    .timestamp
                    .saturating_sub(parent_header.timestamp)
                    .max(1);
                asert_next(
                    tip_header.target,
                    observed,
                    self.config.target_block_time_sec,
                    self.config.asert_half_life_sec,
                    max_target,
                )
                .map_err(ChainError::Difficulty)
            }
        }
    }

    pub fn apply_next_block(&mut self, block: Block) -> Result<BlockApplySummary, ChainError> {
        if block.header.prev_block != self.tip_hash() {
            return Err(ChainError::PrevBlockMustBeTip {
                expected_tip: self.tip_hash(),
                got_prev: block.header.prev_block,
            });
        }
        self.validate_contextual_timestamps(&block)?;

        let expected_target = self.expected_target_for_next_block()?;
        if block.header.target != expected_target {
            return Err(ChainError::UnexpectedTarget {
                expected: expected_target,
                got: block.header.target,
            });
        }

        let height = self.tip_height() + 1;
        let undo = self.collect_block_undo(&block)?;
        let summary = validate_and_apply_block(
            &block,
            height,
            self.config.block_subsidy,
            self.config.coinbase_maturity as u64,
            self.config.network_id.as_bytes(),
            &mut self.utxos,
        )?;
        let block_hash = summary.block_hash;
        self.headers.insert(block_hash, block.header.clone());
        self.blocks.insert(block_hash, block.clone());
        self.main_chain.push(block_hash);

        let prev_work = self
            .cumulative_work
            .get(&block.header.prev_block)
            .expect("tip work must exist")
            .clone();
        let work = prev_work + chainwork_for_target(block.header.target);
        self.cumulative_work.insert(block_hash, work);
        self.undo_data.insert(block_hash, undo);
        Ok(summary)
    }

    pub fn submit_block(&mut self, block: Block) -> Result<BlockSubmissionOutcome, ChainError> {
        validate_block_basic(&block).map_err(ChainError::InvalidBlockStructure)?;

        let block_hash = block.header.block_hash();
        if self.headers.contains_key(&block_hash) {
            return Ok(BlockSubmissionOutcome::AlreadyKnown { block_hash });
        }
        if !self.headers.contains_key(&block.header.prev_block) {
            return Err(ChainError::UnknownParent {
                block_hash,
                parent: block.header.prev_block,
            });
        }
        self.validate_contextual_timestamps(&block)?;

        let parent_work = self
            .cumulative_work
            .get(&block.header.prev_block)
            .expect("parent work must exist")
            .clone();
        let candidate_work = parent_work + chainwork_for_target(block.header.target);

        self.headers.insert(block_hash, block.header.clone());
        self.blocks.insert(block_hash, block);
        self.cumulative_work
            .insert(block_hash, candidate_work.clone());

        let current_tip = self.tip_hash();
        let current_work = self
            .cumulative_work
            .get(&current_tip)
            .expect("tip work must exist")
            .clone();
        if candidate_work <= current_work {
            // Side-branch blocks are not part of the active chain yet.
            self.undo_data.remove(&block_hash);
            return Ok(BlockSubmissionOutcome::StoredSideBranch { block_hash });
        }

        let utxo_backup = self.utxos.clone();
        let main_chain_backup = self.main_chain.clone();
        let undo_backup = self.undo_data.clone();

        let candidate_chain = self.collect_chain_to_genesis(block_hash)?;
        if let Err(err) = self.reorganize_to_chain(&candidate_chain) {
            self.utxos = utxo_backup;
            self.main_chain = main_chain_backup;
            self.undo_data = undo_backup;
            self.headers.remove(&block_hash);
            self.blocks.remove(&block_hash);
            self.cumulative_work.remove(&block_hash);
            return Err(err);
        }

        let new_tip = self.tip_hash();
        if self
            .headers
            .get(&new_tip)
            .expect("new tip header must exist")
            .prev_block
            == current_tip
        {
            return Ok(BlockSubmissionOutcome::ExtendedTip {
                new_tip,
                new_height: self.tip_height(),
            });
        }

        Ok(BlockSubmissionOutcome::Reorged {
            old_tip: current_tip,
            new_tip,
            new_height: self.tip_height(),
        })
    }

    fn collect_chain_to_genesis(&self, tip_hash: Hash256) -> Result<Vec<Hash256>, ChainError> {
        let genesis_hash = self.main_chain[0];
        let mut cursor = tip_hash;
        let mut reversed = Vec::<Hash256>::new();

        loop {
            reversed.push(cursor);
            if cursor == genesis_hash {
                break;
            }

            let header = self
                .headers
                .get(&cursor)
                .ok_or(ChainError::MissingHeader { block_hash: cursor })?;
            if !self.headers.contains_key(&header.prev_block) {
                return Err(ChainError::UnknownParent {
                    block_hash: cursor,
                    parent: header.prev_block,
                });
            }
            cursor = header.prev_block;
        }

        reversed.reverse();
        Ok(reversed)
    }

    fn reorganize_to_chain(&mut self, chain_hashes: &[Hash256]) -> Result<(), ChainError> {
        let Some(_) = chain_hashes.first() else {
            return Err(ChainError::InvalidRuntime(
                "candidate chain cannot be empty".to_owned(),
            ));
        };

        let fork_height = self.find_fork_height(chain_hashes)?;
        while self.main_chain.len().saturating_sub(1) > fork_height {
            self.disconnect_tip_block()?;
        }
        for hash in chain_hashes.iter().copied().skip(fork_height + 1) {
            self.connect_known_block(hash)?;
        }
        Ok(())
    }

    fn find_fork_height(&self, chain_hashes: &[Hash256]) -> Result<usize, ChainError> {
        let mut fork = None;
        for (height, candidate_hash) in chain_hashes.iter().enumerate() {
            match self.main_chain.get(height) {
                Some(local_hash) if local_hash == candidate_hash => {
                    fork = Some(height);
                }
                _ => break,
            }
        }
        fork.ok_or_else(|| {
            ChainError::InvalidRuntime("candidate chain does not share local genesis".to_owned())
        })
    }

    fn connect_known_block(&mut self, block_hash: Hash256) -> Result<(), ChainError> {
        let block = self
            .blocks
            .get(&block_hash)
            .ok_or(ChainError::MissingBlock { block_hash })?
            .clone();

        if block.header.prev_block != self.tip_hash() {
            return Err(ChainError::PrevBlockMustBeTip {
                expected_tip: self.tip_hash(),
                got_prev: block.header.prev_block,
            });
        }
        self.validate_contextual_timestamps(&block)?;
        let expected_target = self.expected_target_for_next_block()?;
        if block.header.target != expected_target {
            return Err(ChainError::UnexpectedTarget {
                expected: expected_target,
                got: block.header.target,
            });
        }

        let undo = self.collect_block_undo(&block)?;
        let next_height = self.tip_height().saturating_add(1);
        validate_and_apply_block(
            &block,
            next_height,
            self.config.block_subsidy,
            self.config.coinbase_maturity as u64,
            self.config.network_id.as_bytes(),
            &mut self.utxos,
        )?;
        self.main_chain.push(block_hash);
        self.undo_data.insert(block_hash, undo);
        Ok(())
    }

    fn disconnect_tip_block(&mut self) -> Result<(), ChainError> {
        if self.main_chain.len() <= 1 {
            return Err(ChainError::InvalidRuntime(
                "cannot disconnect genesis block".to_owned(),
            ));
        }
        let tip_hash = self.tip_hash();
        let undo = self
            .undo_data
            .remove(&tip_hash)
            .ok_or(ChainError::MissingUndoData {
                block_hash: tip_hash,
            })?;

        for outpoint in undo.created_outpoints {
            if self.utxos.remove(&outpoint).is_none() {
                return Err(ChainError::DisconnectMissingCreatedUtxo {
                    block_hash: tip_hash,
                    outpoint,
                });
            }
        }
        for (outpoint, entry) in undo.spent_entries {
            self.utxos.insert(outpoint, entry);
        }
        self.main_chain.pop();
        Ok(())
    }

    fn collect_block_undo(&self, block: &Block) -> Result<BlockUndo, ChainError> {
        let block_hash = block.header.block_hash();
        let mut spent_entries = Vec::<(scam_core::OutPoint, UtxoEntry)>::new();
        for tx in block.transactions.iter().skip(1) {
            for input in &tx.inputs {
                let utxo =
                    self.utxos
                        .get(&input.prev_out)
                        .ok_or(ChainError::MissingUndoSpentUtxo {
                            block_hash,
                            outpoint: input.prev_out.clone(),
                        })?;
                spent_entries.push((input.prev_out.clone(), utxo.clone()));
            }
        }

        let mut created_outpoints = Vec::<scam_core::OutPoint>::new();
        for tx in &block.transactions {
            let txid = tx.txid();
            for (vout, _) in tx.outputs.iter().enumerate() {
                created_outpoints.push(scam_core::OutPoint {
                    txid,
                    vout: vout as u32,
                });
            }
        }

        Ok(BlockUndo {
            spent_entries,
            created_outpoints,
        })
    }
}

fn current_unix_timestamp() -> Result<u64, ChainError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ChainError::InvalidRuntime(format!("system clock before unix epoch: {e}")))?;
    Ok(now.as_secs())
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("chain config error: {0}")]
    Config(#[from] scam_core::ChainConfigError),
    #[error("tx/block validation error: {0}")]
    Validation(#[from] scam_consensus::TxValidationError),
    #[error("difficulty retarget error: {0}")]
    Difficulty(#[source] scam_consensus::difficulty::DifficultyError),
    #[error("invalid block structure: {0}")]
    InvalidBlockStructure(#[from] BlockValidationError),
    #[error("block prev hash must point to current tip: expected {expected_tip}, got {got_prev}")]
    PrevBlockMustBeTip {
        expected_tip: Hash256,
        got_prev: Hash256,
    },
    #[error("unknown parent for block {block_hash}: parent={parent}")]
    UnknownParent {
        block_hash: Hash256,
        parent: Hash256,
    },
    #[error("missing header for block {block_hash}")]
    MissingHeader { block_hash: Hash256 },
    #[error("missing block body for block {block_hash}")]
    MissingBlock { block_hash: Hash256 },
    #[error("missing undo data for connected block {block_hash}")]
    MissingUndoData { block_hash: Hash256 },
    #[error("cannot build undo data for block {block_hash}: missing spent utxo {outpoint:?}")]
    MissingUndoSpentUtxo {
        block_hash: Hash256,
        outpoint: scam_core::OutPoint,
    },
    #[error("disconnect failed for block {block_hash}: missing created utxo {outpoint:?}")]
    DisconnectMissingCreatedUtxo {
        block_hash: Hash256,
        outpoint: scam_core::OutPoint,
    },
    #[error("unexpected block target: expected {expected}, got {got}")]
    UnexpectedTarget { expected: Target, got: Target },
    #[error("unexpected genesis block hash: expected {expected}, got {got}")]
    UnexpectedGenesis { expected: Hash256, got: Hash256 },
    #[error("block {block_hash} timestamp too old: got={got}, median-time-past={median_time_past}")]
    TimestampTooOld {
        block_hash: Hash256,
        median_time_past: u64,
        got: u64,
    },
    #[error("block {block_hash} timestamp too far in future: got={got}, max_allowed={max_allowed}")]
    TimestampTooFarInFuture {
        block_hash: Hash256,
        got: u64,
        max_allowed: u64,
    },
    #[error("{0}")]
    InvalidRuntime(String),
}

#[cfg(test)]
mod tests {
    use scam_core::{OutPoint, Transaction, TxIn, TxOut};
    use scam_miner::{BlockTemplate, mine_block};

    use super::{asert_next, chainwork_for_target, lwma_next, retarget_next};
    use crate::{BlockSubmissionOutcome, ChainError, ChainRuntime};

    fn coinbase(value: u64, key_hash20: [u8; 20], tag: &[u8]) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: tag.to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut { value, key_hash20 }],
            lock_time: 0,
        }
    }

    #[test]
    fn runtime_initializes_from_config() {
        let config_raw = include_str!("../../../config/devnet.toml");
        let config: scam_core::ChainConfig = toml::from_str(config_raw).expect("config parse");
        let runtime = ChainRuntime::from_config(config).expect("runtime init");
        assert_eq!(runtime.tip_height(), 0);
        assert_eq!(runtime.block_hashes().len(), 1);
        assert_eq!(runtime.utxo_len(), 1);
        assert_eq!(runtime.utxo_set().len(), runtime.utxo_len());
    }

    #[test]
    fn runtime_accessors_track_height_and_cumulative_work() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let prev_work = runtime.cumulative_work().clone();
        let target = runtime.expected_target_for_next_block().expect("target");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp + 30,
            target,
            transactions: vec![coinbase(config.block_subsidy, reward, b"accessor-work")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        assert_eq!(runtime.tip_height(), 1);
        assert_eq!(runtime.utxo_set().len(), runtime.utxo_len());
        assert!(
            runtime
                .utxo_set()
                .values()
                .any(|entry| entry.created_height == runtime.tip_height()),
            "new outputs should be tagged with current block height"
        );
        let expected_work = prev_work + chainwork_for_target(target);
        assert_eq!(*runtime.cumulative_work(), expected_work);
    }

    #[test]
    fn expected_target_windowed_returns_tip_target_between_boundaries() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Windowed;
        config.difficulty_adjustment_window = 20;
        let runtime = ChainRuntime::from_config(config).expect("runtime");
        let expected = runtime.expected_target_for_next_block().expect("target");
        assert_eq!(expected, runtime.tip_header().target);
    }

    #[test]
    fn expected_target_windowed_uses_retarget_math_at_boundary() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Windowed;
        config.difficulty_adjustment_window = 2;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp.saturating_add(30),
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"w1")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        let tip_hash = runtime.tip_hash();
        let overridden_tip_target = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .target = overridden_tip_target;

        let start_hash = runtime.block_hash_at_height(0).expect("genesis");
        let start_ts = runtime
            .headers
            .get(&start_hash)
            .expect("genesis header")
            .timestamp;
        let tip_ts = runtime.tip_header().timestamp;
        let expected = retarget_next(
            overridden_tip_target,
            tip_ts.saturating_sub(start_ts).max(1),
            2 * config.target_block_time_sec,
            config.difficulty_clamp_down,
            config.difficulty_clamp_up,
            config.genesis_target().expect("max target"),
        )
        .expect("retarget");

        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn expected_target_lwma_uses_tip_target_until_history_is_ready() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Lwma;
        config.difficulty_adjustment_window = 20;
        let runtime = ChainRuntime::from_config(config).expect("runtime");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            runtime.tip_header().target
        );
    }

    #[test]
    fn expected_target_lwma_matches_formula_when_history_available() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Lwma;
        config.difficulty_adjustment_window = 3;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        for i in 0..3 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp: runtime.tip_header().timestamp + (i + 1) as u64 * 15,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("lwma-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
        }

        let window = config.difficulty_adjustment_window as usize;
        let history = runtime.main_chain.len();
        let start = history - (window + 1);
        let target_override = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        let base_ts = 1_700_000_000u64;
        for (idx, height) in (start..history).enumerate() {
            let hash = runtime.main_chain[height];
            let header = runtime.headers.get_mut(&hash).expect("header");
            header.target = target_override;
            header.timestamp = base_ts + (idx as u64) * 30;
        }

        let mut targets = Vec::with_capacity(window + 1);
        let mut timestamps = Vec::with_capacity(window + 1);
        for height in start..history {
            let hash = runtime.main_chain[height];
            let header = runtime.headers.get(&hash).expect("header");
            targets.push(header.target);
            timestamps.push(header.timestamp);
        }
        let expected = lwma_next(
            &targets,
            &timestamps,
            config.target_block_time_sec,
            config.genesis_target().expect("max target"),
        )
        .expect("lwma");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn expected_target_asert_matches_formula_after_first_block() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Asert;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp.saturating_add(45),
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"asert-1")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        let tip_hash = runtime.tip_hash();
        let override_target = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .target = override_target;

        let tip_header = runtime.tip_header().clone();
        let parent = runtime
            .headers
            .get(&tip_header.prev_block)
            .expect("parent header");
        let expected = asert_next(
            override_target,
            tip_header.timestamp.saturating_sub(parent.timestamp).max(1),
            config.target_block_time_sec,
            config.asert_half_life_sec,
            config.genesis_target().expect("max target"),
        )
        .expect("asert");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn validate_contextual_timestamps_rejects_unknown_parent() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let block = scam_core::Block {
            header: scam_core::BlockHeader {
                version: 1,
                prev_block: scam_core::Hash256([9u8; 32]),
                merkle_root: scam_core::Hash256::ZERO,
                timestamp: runtime.tip_header().timestamp.saturating_add(1),
                target: config.genesis_target().expect("target"),
                nonce: 0,
            },
            transactions: vec![coinbase(
                config.block_subsidy,
                config.genesis_reward_key_hash20().expect("key"),
                b"unknown-parent",
            )],
        };
        let err = runtime
            .validate_contextual_timestamps(&block)
            .expect_err("must reject unknown parent");
        assert!(matches!(err, ChainError::MissingHeader { .. }));
    }

    #[test]
    fn apply_next_block_rejects_unexpected_target_and_accepts_expected_target() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let expected_target = runtime.expected_target_for_next_block().expect("target");
        let wrong_target = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        assert_ne!(wrong_target, expected_target);

        let wrong_block = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp.saturating_add(30),
            target: wrong_target,
            transactions: vec![coinbase(config.block_subsidy, reward, b"wrong-target")],
        }
        .build_with_nonce(0);
        let err = runtime
            .apply_next_block(wrong_block)
            .expect_err("must reject unexpected target");
        assert!(matches!(err, ChainError::UnexpectedTarget { .. }));

        let ok_block = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp.saturating_add(30),
            target: expected_target,
            transactions: vec![coinbase(config.block_subsidy, reward, b"right-target")],
        };
        let mined = mine_block(&ok_block, 200_000).expect("mine");
        runtime.apply_next_block(mined).expect("accept block");
    }

    #[test]
    fn runtime_mines_and_applies_sequential_blocks() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_adjustment_window = 2;
        config.difficulty_clamp_up = 4.0;
        config.difficulty_clamp_down = 0.25;
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let mut timestamp = runtime.tip_header().timestamp + 10;
        for i in 0..3 {
            let target = runtime
                .expected_target_for_next_block()
                .expect("expected target");
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp,
                target,
                transactions: vec![coinbase(
                    config.block_subsidy,
                    config.genesis_reward_key_hash20().expect("key"),
                    format!("b{i}").as_bytes(),
                )],
            };
            let mined = mine_block(&template, 200_000).expect("block mined");
            runtime.apply_next_block(mined).expect("apply");
            timestamp += if i == 0 { 10 } else { 120 };
        }

        assert_eq!(runtime.tip_height(), 3);
        assert_eq!(runtime.block_hashes().len(), 4);
    }

    #[test]
    fn side_branch_with_more_work_triggers_reorg() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_adjustment_window = 50;
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let mut timestamp = runtime.tip_header().timestamp + 30;
        for i in 0..4 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    config.genesis_reward_key_hash20().expect("key"),
                    format!("main-{i}").as_bytes(),
                )],
            };
            let mined = mine_block(&template, 300_000).expect("main mined");
            runtime.apply_next_block(mined).expect("main apply");
            timestamp += 30;
        }
        let old_tip = runtime.tip_hash();
        let fork_point = runtime.block_hash_at_height(1).expect("fork height exists");
        let fork_target = runtime
            .header_by_hash(&fork_point)
            .expect("fork header")
            .target;
        let mut fork_prev = fork_point;
        let mut fork_ts = runtime
            .header_by_hash(&fork_point)
            .expect("fork header")
            .timestamp
            + 20;

        let mut saw_reorg = false;
        for i in 0..6 {
            let template = BlockTemplate {
                version: 1,
                prev_block: fork_prev,
                timestamp: fork_ts,
                target: fork_target,
                transactions: vec![coinbase(
                    config.block_subsidy,
                    config.genesis_reward_key_hash20().expect("key"),
                    format!("fork-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 300_000).expect("fork mined");
            fork_prev = block.header.block_hash();
            let outcome = runtime.submit_block(block).expect("submit");
            if matches!(outcome, BlockSubmissionOutcome::Reorged { .. }) {
                saw_reorg = true;
            }
            fork_ts += 20;
        }

        assert!(saw_reorg, "expected at least one reorg event");
        assert_ne!(runtime.tip_hash(), old_tip);
    }

    #[test]
    fn block_timestamp_must_be_greater_than_median_time_past() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_adjustment_window = 50;
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let reward = config.genesis_reward_key_hash20().expect("key");

        let mut timestamp = runtime.tip_header().timestamp + 30;
        for i in 0..11 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("mtp-main-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
            timestamp += 30;
        }

        let mtp = runtime
            .median_time_past(runtime.tip_hash())
            .expect("median-time-past");
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: mtp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"mtp-reject")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        let err = runtime.apply_next_block(block).expect_err("must reject");
        assert!(matches!(err, ChainError::TimestampTooOld { .. }));
    }

    #[test]
    fn block_timestamp_too_far_in_future_is_rejected() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let now = super::current_unix_timestamp().expect("now");
        let future_timestamp = now + super::MAX_FUTURE_BLOCK_TIME_SEC + 1;

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: future_timestamp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(
                config.block_subsidy,
                config.genesis_reward_key_hash20().expect("key"),
                b"future-reject",
            )],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        let err = runtime.apply_next_block(block).expect_err("must reject");
        assert!(matches!(err, ChainError::TimestampTooFarInFuture { .. }));
    }

    #[test]
    fn block_timestamp_within_future_window_is_accepted() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let now = super::current_unix_timestamp().expect("now");

        // Keep this comfortably below the 2-hour guard so tiny clock drift during validation
        // does not make the test flaky.
        let near_future_timestamp = now + 4_000;
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: near_future_timestamp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"within-future")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime
            .apply_next_block(block)
            .expect("timestamp below future window should pass");
    }

    #[test]
    fn block_timestamp_at_future_window_boundary_is_accepted() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let now = super::current_unix_timestamp().expect("now");

        let boundary_timestamp = now + super::MAX_FUTURE_BLOCK_TIME_SEC;
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: boundary_timestamp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"future-boundary")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime
            .apply_next_block(block)
            .expect("timestamp on future boundary should pass");
    }

    #[test]
    fn expected_target_windowed_uses_subtraction_index_at_boundary() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Windowed;
        config.difficulty_adjustment_window = 3;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        for i in 0..5 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp: runtime.tip_header().timestamp + 30 + i as u64,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("window-boundary-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
        }
        assert_eq!(runtime.tip_height(), 5);

        let tip_hash = runtime.tip_hash();
        let height2 = runtime.block_hash_at_height(2).expect("h2 hash");
        let height3 = runtime.block_hash_at_height(3).expect("h3 hash");
        let target_override = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .target = target_override;
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .timestamp = 10_000;
        runtime
            .headers
            .get_mut(&height2)
            .expect("height2 header")
            .timestamp = 1_000;
        runtime
            .headers
            .get_mut(&height3)
            .expect("height3 header")
            .timestamp = 9_000;

        let expected = retarget_next(
            target_override,
            10_000u64.saturating_sub(9_000),
            3 * config.target_block_time_sec,
            config.difficulty_clamp_down,
            config.difficulty_clamp_up,
            config.genesis_target().expect("max target"),
        )
        .expect("retarget");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn expected_target_lwma_uses_history_window_offset_formula() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Lwma;
        config.difficulty_adjustment_window = 3;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        for i in 0..7 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp: runtime.tip_header().timestamp + 40 + i as u64,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("lwma-window-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
        }

        let history = runtime.main_chain.len();
        let window = config.difficulty_adjustment_window as usize;
        assert_eq!(history, 8);
        let start = history - (window + 1);
        let timestamps = [1_000u64, 1_020, 1_060, 1_100, 1_400, 1_450, 1_470, 1_900];
        for (idx, hash) in runtime.main_chain.iter().enumerate() {
            let header = runtime.headers.get_mut(hash).expect("header");
            header.timestamp = timestamps[idx];
            let mut target = [0xffu8; 32];
            target[0] = 0;
            target[1] = 0xffu8.saturating_sub((idx as u8) * 16);
            header.target = scam_core::Target(target);
        }

        let mut targets = Vec::with_capacity(window + 1);
        let mut sampled_timestamps = Vec::with_capacity(window + 1);
        for height in start..history {
            let hash = runtime.main_chain[height];
            let header = runtime.headers.get(&hash).expect("header");
            targets.push(header.target);
            sampled_timestamps.push(header.timestamp);
        }
        let expected = lwma_next(
            &targets,
            &sampled_timestamps,
            config.target_block_time_sec,
            config.genesis_target().expect("max target"),
        )
        .expect("lwma");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn submit_block_extending_tip_reports_extended_tip_outcome() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp + 30,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"submit-extend")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        let submitted_hash = block.header.block_hash();
        let outcome = runtime.submit_block(block).expect("submit");
        match outcome {
            BlockSubmissionOutcome::ExtendedTip {
                new_tip,
                new_height,
            } => {
                assert_eq!(new_tip, submitted_hash);
                assert_eq!(new_height, 1);
            }
            other => panic!("expected ExtendedTip, got {other:?}"),
        }
    }

    #[test]
    fn runtime_can_restore_from_ordered_blocks() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp + 30,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(
                config.block_subsidy,
                config.genesis_reward_key_hash20().expect("key"),
                b"restore-1",
            )],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        let ordered = runtime.main_chain_blocks().expect("export");
        let restored = ChainRuntime::from_ordered_blocks(config, ordered).expect("restore");
        assert_eq!(restored.tip_height(), runtime.tip_height());
        assert_eq!(restored.tip_hash(), runtime.tip_hash());
        assert_eq!(restored.utxo_len(), runtime.utxo_len());
    }
}
