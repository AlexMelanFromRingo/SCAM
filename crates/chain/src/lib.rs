use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use num_bigint::BigUint;
use scam_consensus::{
    BlockApplySummary, BlockValidationError, UtxoSet, asert_next, chainwork_for_target, lwma_next,
    retarget_next, validate_and_apply_block, validate_block_basic,
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
            return Ok(BlockSubmissionOutcome::StoredSideBranch { block_hash });
        }

        let candidate_chain = self.collect_chain_to_genesis(block_hash)?;
        let replayed = match self.replay_chain(&candidate_chain) {
            Ok(runtime) => runtime,
            Err(err) => {
                self.headers.remove(&block_hash);
                self.blocks.remove(&block_hash);
                self.cumulative_work.remove(&block_hash);
                return Err(err);
            }
        };

        self.main_chain = candidate_chain;
        self.utxos = replayed.utxos;

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

    fn replay_chain(&self, chain_hashes: &[Hash256]) -> Result<Self, ChainError> {
        let Some(genesis_hash) = chain_hashes.first().copied() else {
            return Err(ChainError::InvalidRuntime(
                "candidate chain cannot be empty".to_owned(),
            ));
        };

        let genesis = self
            .blocks
            .get(&genesis_hash)
            .ok_or(ChainError::MissingBlock {
                block_hash: genesis_hash,
            })?
            .clone();
        let mut replay = ChainRuntime::new(self.config.clone(), genesis)?;

        for hash in chain_hashes.iter().copied().skip(1) {
            let block = self
                .blocks
                .get(&hash)
                .ok_or(ChainError::MissingBlock { block_hash: hash })?
                .clone();
            replay.apply_next_block(block)?;
        }
        Ok(replay)
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
