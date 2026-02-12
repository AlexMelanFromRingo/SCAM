use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Hash256;
use crate::hash::{ParseHexError, decode_hex_array};
use crate::merkle::merkle_root;
use crate::target::Target;
use crate::types::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    pub network_id: String,
    pub target_block_time_sec: u64,
    pub difficulty_adjustment_window: u32,
    pub difficulty_clamp_up: f64,
    pub difficulty_clamp_down: f64,
    pub max_block_size: u32,
    pub max_tx_size: u32,
    pub max_mempool_txs: u32,
    #[serde(default = "default_min_relay_fee_per_kb")]
    pub min_relay_fee_per_kb: u64,
    #[serde(default = "default_max_orphan_txs")]
    pub max_orphan_txs: u32,
    #[serde(default = "default_orphan_ttl_sec")]
    pub orphan_ttl_sec: u64,
    pub coinbase_maturity: u32,
    pub block_subsidy: u64,
    pub hrp: String,
    pub genesis_message: String,
    pub genesis_timestamp: u64,
    pub genesis_target: String,
    pub genesis_nonce: u64,
    pub genesis_reward_key_hash20: String,
}

impl ChainConfig {
    pub fn validate(&self) -> Result<(), ChainConfigError> {
        if self.network_id.trim().is_empty() {
            return Err(ChainConfigError::InvalidField(
                "network_id must not be empty".to_owned(),
            ));
        }
        if self.target_block_time_sec == 0 {
            return Err(ChainConfigError::InvalidField(
                "target_block_time_sec must be > 0".to_owned(),
            ));
        }
        if self.difficulty_adjustment_window == 0 {
            return Err(ChainConfigError::InvalidField(
                "difficulty_adjustment_window must be > 0".to_owned(),
            ));
        }
        if self.difficulty_clamp_up < 1.0 {
            return Err(ChainConfigError::InvalidField(
                "difficulty_clamp_up must be >= 1.0".to_owned(),
            ));
        }
        if !(0.0..=1.0).contains(&self.difficulty_clamp_down) || self.difficulty_clamp_down == 0.0 {
            return Err(ChainConfigError::InvalidField(
                "difficulty_clamp_down must be in (0.0, 1.0]".to_owned(),
            ));
        }
        if self.max_block_size == 0 || self.max_tx_size == 0 {
            return Err(ChainConfigError::InvalidField(
                "max sizes must be > 0".to_owned(),
            ));
        }
        if self.max_tx_size > self.max_block_size {
            return Err(ChainConfigError::InvalidField(
                "max_tx_size must be <= max_block_size".to_owned(),
            ));
        }
        if self.max_mempool_txs == 0 {
            return Err(ChainConfigError::InvalidField(
                "max_mempool_txs must be > 0".to_owned(),
            ));
        }
        if self.max_orphan_txs == 0 {
            return Err(ChainConfigError::InvalidField(
                "max_orphan_txs must be > 0".to_owned(),
            ));
        }
        if self.orphan_ttl_sec == 0 {
            return Err(ChainConfigError::InvalidField(
                "orphan_ttl_sec must be > 0".to_owned(),
            ));
        }
        if self.hrp.trim().is_empty() {
            return Err(ChainConfigError::InvalidField(
                "hrp must not be empty".to_owned(),
            ));
        }
        if !self.hrp.starts_with('s') {
            return Err(ChainConfigError::InvalidField(
                "hrp must start with 's'".to_owned(),
            ));
        }
        if self.genesis_message.trim().is_empty() {
            return Err(ChainConfigError::InvalidField(
                "genesis_message must not be empty".to_owned(),
            ));
        }

        self.genesis_target()?;
        self.genesis_reward_key_hash20()?;
        Ok(())
    }

    pub fn genesis_target(&self) -> Result<Target, ChainConfigError> {
        let target = Target::from_hex(&self.genesis_target)?;
        if target == Target::MIN {
            return Err(ChainConfigError::InvalidField(
                "genesis_target must be non-zero".to_owned(),
            ));
        }
        Ok(target)
    }

    pub fn genesis_reward_key_hash20(&self) -> Result<[u8; 20], ChainConfigError> {
        decode_hex_array(&self.genesis_reward_key_hash20).map_err(ChainConfigError::from)
    }

    pub fn build_genesis_block(&self) -> Result<Block, ChainConfigError> {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: self.genesis_message.as_bytes().to_vec(),
                pubkey_compressed: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: self.block_subsidy,
                key_hash20: self.genesis_reward_key_hash20()?,
            }],
            lock_time: 0,
        };
        let merkle = merkle_root(&[coinbase_tx.txid()]);

        Ok(Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: merkle,
                timestamp: self.genesis_timestamp,
                target: self.genesis_target()?,
                nonce: self.genesis_nonce,
            },
            transactions: vec![coinbase_tx],
        })
    }
}

const fn default_min_relay_fee_per_kb() -> u64 {
    1_000
}

const fn default_max_orphan_txs() -> u32 {
    5_000
}

const fn default_orphan_ttl_sec() -> u64 {
    20 * 60
}

#[derive(Debug, Error)]
pub enum ChainConfigError {
    #[error("{0}")]
    InvalidField(String),
    #[error("hex parse error: {0}")]
    Hex(#[from] ParseHexError),
}

#[cfg(test)]
mod tests {
    use crate::ChainConfig;

    #[test]
    fn config_builds_genesis_block() {
        let cfg = ChainConfig {
            network_id: "devnet".to_owned(),
            target_block_time_sec: 120,
            difficulty_adjustment_window: 20,
            difficulty_clamp_up: 4.0,
            difficulty_clamp_down: 0.25,
            max_block_size: 1_000_000,
            max_tx_size: 100_000,
            max_mempool_txs: 1_000,
            min_relay_fee_per_kb: 1_000,
            max_orphan_txs: 5_000,
            orphan_ttl_sec: 1_200,
            coinbase_maturity: 100,
            block_subsidy: 5_000_000_000,
            hrp: "sd".to_owned(),
            genesis_message: "SCAM genesis".to_owned(),
            genesis_timestamp: 1_770_763_200,
            genesis_target: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_owned(),
            genesis_nonce: 0,
            genesis_reward_key_hash20: "0000000000000000000000000000000000000000".to_owned(),
        };

        cfg.validate().expect("config should validate");
        let genesis = cfg.build_genesis_block().expect("genesis should build");
        assert!(genesis.transactions[0].is_coinbase());
    }

    #[test]
    fn config_rejects_non_s_address_prefix() {
        let mut cfg = ChainConfig {
            network_id: "devnet".to_owned(),
            target_block_time_sec: 120,
            difficulty_adjustment_window: 20,
            difficulty_clamp_up: 4.0,
            difficulty_clamp_down: 0.25,
            max_block_size: 1_000_000,
            max_tx_size: 100_000,
            max_mempool_txs: 1_000,
            min_relay_fee_per_kb: 1_000,
            max_orphan_txs: 5_000,
            orphan_ttl_sec: 1_200,
            coinbase_maturity: 100,
            block_subsidy: 5_000_000_000,
            hrp: "sd".to_owned(),
            genesis_message: "SCAM genesis".to_owned(),
            genesis_timestamp: 1_770_763_200,
            genesis_target: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_owned(),
            genesis_nonce: 0,
            genesis_reward_key_hash20: "0000000000000000000000000000000000000000".to_owned(),
        };
        cfg.hrp = "x".to_owned();
        let err = cfg.validate().expect_err("invalid hrp prefix must fail");
        assert!(matches!(err, super::ChainConfigError::InvalidField(_)));
    }

    #[test]
    fn config_applies_defaults_for_mempool_policy_fields() {
        let raw = r#"
network_id = "devnet"
target_block_time_sec = 120
difficulty_adjustment_window = 20
difficulty_clamp_up = 4.0
difficulty_clamp_down = 0.25
max_block_size = 1_000_000
max_tx_size = 100_000
max_mempool_txs = 1_000
coinbase_maturity = 100
block_subsidy = 5_000_000_000
hrp = "sd"
genesis_message = "SCAM genesis"
genesis_timestamp = 1_770_763_200
genesis_target = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
genesis_nonce = 0
genesis_reward_key_hash20 = "0000000000000000000000000000000000000000"
"#;
        let cfg: ChainConfig = toml::from_str(raw).expect("config parse");
        assert_eq!(cfg.min_relay_fee_per_kb, 1_000);
        assert_eq!(cfg.max_orphan_txs, 5_000);
        assert_eq!(cfg.orphan_ttl_sec, 1_200);
        cfg.validate().expect("validate");
    }
}
