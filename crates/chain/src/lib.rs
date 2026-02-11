use std::collections::HashMap;

use num_bigint::BigUint;
use scam_consensus::{
    BlockApplySummary, UtxoSet, chainwork_for_target, retarget_next, validate_and_apply_block,
};
use scam_core::{Block, BlockHeader, ChainConfig, Hash256, Target};
use thiserror::Error;

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

    pub fn new(config: ChainConfig, genesis: Block) -> Result<Self, ChainError> {
        let mut utxos = UtxoSet::new();
        let applied = validate_and_apply_block(
            &genesis,
            0,
            config.block_subsidy,
            config.coinbase_maturity as u64,
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

    pub fn expected_target_for_next_block(&self) -> Result<Target, ChainError> {
        let next_height = self.tip_height() + 1;
        let window = self.config.difficulty_adjustment_window as u64;
        if window == 0 {
            return Err(ChainError::InvalidRuntime(
                "difficulty_adjustment_window must be > 0".to_owned(),
            ));
        }

        let tip_header = self.tip_header();
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
        let max_target = self.config.genesis_target()?;

        let next_target = retarget_next(
            tip_header.target,
            actual_timespan,
            expected_timespan,
            self.config.difficulty_clamp_down,
            self.config.difficulty_clamp_up,
            max_target,
        )
        .map_err(ChainError::Difficulty)?;

        Ok(next_target)
    }

    pub fn apply_next_block(&mut self, block: Block) -> Result<BlockApplySummary, ChainError> {
        if block.header.prev_block != self.tip_hash() {
            return Err(ChainError::PrevBlockMustBeTip {
                expected_tip: self.tip_hash(),
                got_prev: block.header.prev_block,
            });
        }

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
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("chain config error: {0}")]
    Config(#[from] scam_core::ChainConfigError),
    #[error("tx/block validation error: {0}")]
    Validation(#[from] scam_consensus::TxValidationError),
    #[error("difficulty retarget error: {0}")]
    Difficulty(#[source] scam_consensus::difficulty::DifficultyError),
    #[error("block prev hash must point to current tip: expected {expected_tip}, got {got_prev}")]
    PrevBlockMustBeTip {
        expected_tip: Hash256,
        got_prev: Hash256,
    },
    #[error("unexpected block target: expected {expected}, got {got}")]
    UnexpectedTarget { expected: Target, got: Target },
    #[error("{0}")]
    InvalidRuntime(String),
}

#[cfg(test)]
mod tests {
    use scam_core::{OutPoint, Transaction, TxIn, TxOut};
    use scam_miner::{BlockTemplate, mine_block};

    use crate::ChainRuntime;

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
}
