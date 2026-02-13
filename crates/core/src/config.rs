use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Hash256;
use crate::hash::{ParseHexError, decode_hex_array};
use crate::merkle::merkle_root;
use crate::target::Target;
use crate::types::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DifficultyAlgorithm {
    Windowed,
    Lwma,
    Asert,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    pub network_id: String,
    pub target_block_time_sec: u64,
    pub difficulty_adjustment_window: u32,
    #[serde(default = "default_difficulty_algorithm")]
    pub difficulty_algorithm: DifficultyAlgorithm,
    #[serde(default = "default_asert_half_life_sec")]
    pub asert_half_life_sec: u64,
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
    #[serde(default = "default_p2p_max_outbound_per_bucket")]
    pub p2p_max_outbound_per_bucket: u32,
    #[serde(default = "default_dns_seeds")]
    pub dns_seeds: Vec<String>,
    #[serde(default = "default_p2p_max_inv_items")]
    pub p2p_max_inv_items: usize,
    #[serde(default = "default_p2p_ban_threshold")]
    pub p2p_ban_threshold: u32,
    #[serde(default = "default_p2p_replacement_window_sec")]
    pub p2p_replacement_window_sec: u64,
    #[serde(default = "default_p2p_replacement_max_per_peer")]
    pub p2p_replacement_max_per_peer: usize,
    #[serde(default = "default_p2p_replacement_penalty")]
    pub p2p_replacement_penalty: u32,
    pub coinbase_maturity: u32,
    pub block_subsidy: u64,
    pub hrp: String,
    #[serde(default = "default_stratum_share_target")]
    pub stratum_share_target: String,
    #[serde(default = "default_stratum_min_share_target")]
    pub stratum_min_share_target: String,
    #[serde(default = "default_stratum_max_share_target")]
    pub stratum_max_share_target: String,
    #[serde(default = "default_stratum_vardiff_target_shares_per_minute")]
    pub stratum_vardiff_target_shares_per_minute: u32,
    #[serde(default = "default_stratum_vardiff_retarget_interval_shares")]
    pub stratum_vardiff_retarget_interval_shares: usize,
    #[serde(default = "default_stratum_vardiff_clamp_up")]
    pub stratum_vardiff_clamp_up: f64,
    #[serde(default = "default_stratum_vardiff_clamp_down")]
    pub stratum_vardiff_clamp_down: f64,
    #[serde(default = "default_stratum_max_rejected_shares")]
    pub stratum_max_rejected_shares: u32,
    #[serde(default = "default_stratum_read_timeout_sec")]
    pub stratum_read_timeout_sec: u64,
    #[serde(default = "default_stratum_keepalive_sec")]
    pub stratum_keepalive_sec: u64,
    #[serde(default = "default_stratum_idle_timeout_sec")]
    pub stratum_idle_timeout_sec: u64,
    #[serde(default = "default_stratum_max_jobs_per_channel")]
    pub stratum_max_jobs_per_channel: usize,
    #[serde(default = "default_stratum_max_active_clients")]
    pub stratum_max_active_clients: usize,
    #[serde(default = "default_stratum_secure_transport")]
    pub stratum_secure_transport: bool,
    #[serde(default = "default_stratum_secure_transport_mode")]
    pub stratum_secure_transport_mode: String,
    #[serde(default = "default_stratum_secure_rekey_interval_messages")]
    pub stratum_secure_rekey_interval_messages: u64,
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
        if self.asert_half_life_sec == 0 {
            return Err(ChainConfigError::InvalidField(
                "asert_half_life_sec must be > 0".to_owned(),
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
        if self.p2p_max_outbound_per_bucket == 0 {
            return Err(ChainConfigError::InvalidField(
                "p2p_max_outbound_per_bucket must be > 0".to_owned(),
            ));
        }
        if self.p2p_max_inv_items == 0 {
            return Err(ChainConfigError::InvalidField(
                "p2p_max_inv_items must be > 0".to_owned(),
            ));
        }
        if self.p2p_ban_threshold == 0 {
            return Err(ChainConfigError::InvalidField(
                "p2p_ban_threshold must be > 0".to_owned(),
            ));
        }
        if self.p2p_replacement_window_sec == 0 {
            return Err(ChainConfigError::InvalidField(
                "p2p_replacement_window_sec must be > 0".to_owned(),
            ));
        }
        if self.p2p_replacement_max_per_peer == 0 {
            return Err(ChainConfigError::InvalidField(
                "p2p_replacement_max_per_peer must be > 0".to_owned(),
            ));
        }
        if self.p2p_replacement_penalty == 0 {
            return Err(ChainConfigError::InvalidField(
                "p2p_replacement_penalty must be > 0".to_owned(),
            ));
        }
        if self.dns_seeds.iter().any(|seed| seed.trim().is_empty()) {
            return Err(ChainConfigError::InvalidField(
                "dns_seeds must not contain empty entries".to_owned(),
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
        let share_target = self.stratum_share_target()?;
        let min_share_target = self.stratum_min_share_target()?;
        let max_share_target = self.stratum_max_share_target()?;
        if min_share_target > max_share_target {
            return Err(ChainConfigError::InvalidField(
                "stratum_min_share_target must be <= stratum_max_share_target".to_owned(),
            ));
        }
        if share_target < min_share_target || share_target > max_share_target {
            return Err(ChainConfigError::InvalidField(
                "stratum_share_target must be within [stratum_min_share_target, stratum_max_share_target]"
                    .to_owned(),
            ));
        }
        if self.stratum_vardiff_target_shares_per_minute == 0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_vardiff_target_shares_per_minute must be > 0".to_owned(),
            ));
        }
        if self.stratum_vardiff_retarget_interval_shares < 2 {
            return Err(ChainConfigError::InvalidField(
                "stratum_vardiff_retarget_interval_shares must be >= 2".to_owned(),
            ));
        }
        if self.stratum_vardiff_clamp_up < 1.0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_vardiff_clamp_up must be >= 1.0".to_owned(),
            ));
        }
        if !(0.0..=1.0).contains(&self.stratum_vardiff_clamp_down)
            || self.stratum_vardiff_clamp_down == 0.0
        {
            return Err(ChainConfigError::InvalidField(
                "stratum_vardiff_clamp_down must be in (0.0, 1.0]".to_owned(),
            ));
        }
        if self.stratum_max_rejected_shares == 0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_max_rejected_shares must be > 0".to_owned(),
            ));
        }
        if self.stratum_read_timeout_sec == 0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_read_timeout_sec must be > 0".to_owned(),
            ));
        }
        if self.stratum_keepalive_sec == 0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_keepalive_sec must be > 0".to_owned(),
            ));
        }
        if self.stratum_idle_timeout_sec == 0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_idle_timeout_sec must be > 0".to_owned(),
            ));
        }
        if self.stratum_keepalive_sec >= self.stratum_idle_timeout_sec {
            return Err(ChainConfigError::InvalidField(
                "stratum_idle_timeout_sec must be > stratum_keepalive_sec".to_owned(),
            ));
        }
        if self.stratum_max_jobs_per_channel == 0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_max_jobs_per_channel must be > 0".to_owned(),
            ));
        }
        if self.stratum_max_active_clients == 0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_max_active_clients must be > 0".to_owned(),
            ));
        }
        if self.stratum_secure_rekey_interval_messages == 0 {
            return Err(ChainConfigError::InvalidField(
                "stratum_secure_rekey_interval_messages must be > 0".to_owned(),
            ));
        }
        if !matches!(
            self.stratum_secure_transport_mode.as_str(),
            "legacy" | "noise_xx"
        ) {
            return Err(ChainConfigError::InvalidField(
                "stratum_secure_transport_mode must be one of: legacy, noise_xx".to_owned(),
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

    pub fn stratum_share_target(&self) -> Result<Target, ChainConfigError> {
        Target::from_hex(&self.stratum_share_target).map_err(ChainConfigError::from)
    }

    pub fn stratum_min_share_target(&self) -> Result<Target, ChainConfigError> {
        Target::from_hex(&self.stratum_min_share_target).map_err(ChainConfigError::from)
    }

    pub fn stratum_max_share_target(&self) -> Result<Target, ChainConfigError> {
        Target::from_hex(&self.stratum_max_share_target).map_err(ChainConfigError::from)
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

const fn default_difficulty_algorithm() -> DifficultyAlgorithm {
    DifficultyAlgorithm::Windowed
}

const fn default_asert_half_life_sec() -> u64 {
    3_600
}

const fn default_max_orphan_txs() -> u32 {
    5_000
}

const fn default_orphan_ttl_sec() -> u64 {
    20 * 60
}

const fn default_p2p_max_outbound_per_bucket() -> u32 {
    2
}

fn default_dns_seeds() -> Vec<String> {
    Vec::new()
}

const fn default_p2p_max_inv_items() -> usize {
    2_000
}

const fn default_p2p_ban_threshold() -> u32 {
    100
}

const fn default_p2p_replacement_window_sec() -> u64 {
    60
}

const fn default_p2p_replacement_max_per_peer() -> usize {
    20
}

const fn default_p2p_replacement_penalty() -> u32 {
    25
}

fn default_stratum_share_target() -> String {
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned()
}

fn default_stratum_min_share_target() -> String {
    "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned()
}

fn default_stratum_max_share_target() -> String {
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned()
}

const fn default_stratum_vardiff_target_shares_per_minute() -> u32 {
    6
}

const fn default_stratum_vardiff_retarget_interval_shares() -> usize {
    24
}

const fn default_stratum_vardiff_clamp_up() -> f64 {
    2.0
}

const fn default_stratum_vardiff_clamp_down() -> f64 {
    0.5
}

const fn default_stratum_max_rejected_shares() -> u32 {
    64
}

const fn default_stratum_read_timeout_sec() -> u64 {
    2
}

const fn default_stratum_keepalive_sec() -> u64 {
    30
}

const fn default_stratum_idle_timeout_sec() -> u64 {
    180
}

const fn default_stratum_max_jobs_per_channel() -> usize {
    64
}

const fn default_stratum_max_active_clients() -> usize {
    256
}

const fn default_stratum_secure_transport() -> bool {
    false
}

fn default_stratum_secure_transport_mode() -> String {
    "noise_xx".to_owned()
}

const fn default_stratum_secure_rekey_interval_messages() -> u64 {
    10_000
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
    use crate::{ChainConfig, DifficultyAlgorithm};

    fn sample_config() -> ChainConfig {
        toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse")
    }

    #[test]
    fn config_builds_genesis_block() {
        let cfg = ChainConfig {
            network_id: "devnet".to_owned(),
            target_block_time_sec: 120,
            difficulty_adjustment_window: 20,
            difficulty_algorithm: DifficultyAlgorithm::Windowed,
            asert_half_life_sec: 3_600,
            difficulty_clamp_up: 4.0,
            difficulty_clamp_down: 0.25,
            max_block_size: 1_000_000,
            max_tx_size: 100_000,
            max_mempool_txs: 1_000,
            min_relay_fee_per_kb: 1_000,
            max_orphan_txs: 5_000,
            orphan_ttl_sec: 1_200,
            p2p_max_outbound_per_bucket: 2,
            dns_seeds: Vec::new(),
            p2p_max_inv_items: 2_000,
            p2p_ban_threshold: 100,
            p2p_replacement_window_sec: 60,
            p2p_replacement_max_per_peer: 20,
            p2p_replacement_penalty: 25,
            coinbase_maturity: 100,
            block_subsidy: 5_000_000_000,
            hrp: "sd".to_owned(),
            stratum_share_target:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_min_share_target:
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_max_share_target:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_vardiff_target_shares_per_minute: 6,
            stratum_vardiff_retarget_interval_shares: 24,
            stratum_vardiff_clamp_up: 2.0,
            stratum_vardiff_clamp_down: 0.5,
            stratum_max_rejected_shares: 64,
            stratum_read_timeout_sec: 2,
            stratum_keepalive_sec: 30,
            stratum_idle_timeout_sec: 180,
            stratum_max_jobs_per_channel: 64,
            stratum_max_active_clients: 256,
            stratum_secure_transport: false,
            stratum_secure_transport_mode: "noise_xx".to_owned(),
            stratum_secure_rekey_interval_messages: 10_000,
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
            difficulty_algorithm: DifficultyAlgorithm::Windowed,
            asert_half_life_sec: 3_600,
            difficulty_clamp_up: 4.0,
            difficulty_clamp_down: 0.25,
            max_block_size: 1_000_000,
            max_tx_size: 100_000,
            max_mempool_txs: 1_000,
            min_relay_fee_per_kb: 1_000,
            max_orphan_txs: 5_000,
            orphan_ttl_sec: 1_200,
            p2p_max_outbound_per_bucket: 2,
            dns_seeds: Vec::new(),
            p2p_max_inv_items: 2_000,
            p2p_ban_threshold: 100,
            p2p_replacement_window_sec: 60,
            p2p_replacement_max_per_peer: 20,
            p2p_replacement_penalty: 25,
            coinbase_maturity: 100,
            block_subsidy: 5_000_000_000,
            hrp: "sd".to_owned(),
            stratum_share_target:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_min_share_target:
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_max_share_target:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_vardiff_target_shares_per_minute: 6,
            stratum_vardiff_retarget_interval_shares: 24,
            stratum_vardiff_clamp_up: 2.0,
            stratum_vardiff_clamp_down: 0.5,
            stratum_max_rejected_shares: 64,
            stratum_read_timeout_sec: 2,
            stratum_keepalive_sec: 30,
            stratum_idle_timeout_sec: 180,
            stratum_max_jobs_per_channel: 64,
            stratum_max_active_clients: 256,
            stratum_secure_transport: false,
            stratum_secure_transport_mode: "noise_xx".to_owned(),
            stratum_secure_rekey_interval_messages: 10_000,
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
        assert_eq!(cfg.difficulty_algorithm, DifficultyAlgorithm::Windowed);
        assert_eq!(cfg.asert_half_life_sec, 3_600);
        assert_eq!(cfg.min_relay_fee_per_kb, 1_000);
        assert_eq!(cfg.max_orphan_txs, 5_000);
        assert_eq!(cfg.orphan_ttl_sec, 1_200);
        assert_eq!(cfg.p2p_max_outbound_per_bucket, 2);
        assert!(cfg.dns_seeds.is_empty());
        assert_eq!(cfg.p2p_max_inv_items, 2_000);
        assert_eq!(cfg.p2p_ban_threshold, 100);
        assert_eq!(cfg.p2p_replacement_window_sec, 60);
        assert_eq!(cfg.p2p_replacement_max_per_peer, 20);
        assert_eq!(cfg.p2p_replacement_penalty, 25);
        assert_eq!(
            cfg.stratum_share_target,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(
            cfg.stratum_min_share_target,
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(
            cfg.stratum_max_share_target,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(cfg.stratum_vardiff_target_shares_per_minute, 6);
        assert_eq!(cfg.stratum_vardiff_retarget_interval_shares, 24);
        assert_eq!(cfg.stratum_vardiff_clamp_up, 2.0);
        assert_eq!(cfg.stratum_vardiff_clamp_down, 0.5);
        assert_eq!(cfg.stratum_max_rejected_shares, 64);
        assert_eq!(cfg.stratum_read_timeout_sec, 2);
        assert_eq!(cfg.stratum_keepalive_sec, 30);
        assert_eq!(cfg.stratum_idle_timeout_sec, 180);
        assert_eq!(cfg.stratum_max_jobs_per_channel, 64);
        assert_eq!(cfg.stratum_max_active_clients, 256);
        assert!(!cfg.stratum_secure_transport);
        assert_eq!(cfg.stratum_secure_transport_mode, "noise_xx");
        assert_eq!(cfg.stratum_secure_rekey_interval_messages, 10_000);
        cfg.validate().expect("validate");
    }

    #[test]
    fn config_rejects_cross_field_violations() {
        let mut cfg = sample_config();
        cfg.max_tx_size = cfg.max_block_size + 1;
        let err = cfg.validate().expect_err("max_tx_size > max_block_size");
        assert!(
            err.to_string()
                .contains("max_tx_size must be <= max_block_size")
        );

        let mut cfg = sample_config();
        cfg.stratum_min_share_target =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        cfg.stratum_max_share_target =
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let err = cfg
            .validate()
            .expect_err("stratum min target above max must fail");
        assert!(
            err.to_string()
                .contains("stratum_min_share_target must be <= stratum_max_share_target")
        );

        let mut cfg = sample_config();
        cfg.stratum_share_target =
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        cfg.stratum_min_share_target =
            "10ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let err = cfg
            .validate()
            .expect_err("share target below min bound must fail");
        assert!(
            err.to_string()
                .contains("stratum_share_target must be within [stratum_min_share_target, stratum_max_share_target]")
        );

        let mut cfg = sample_config();
        cfg.stratum_keepalive_sec = 30;
        cfg.stratum_idle_timeout_sec = 30;
        let err = cfg
            .validate()
            .expect_err("idle timeout equal to keepalive must fail");
        assert!(
            err.to_string()
                .contains("stratum_idle_timeout_sec must be > stratum_keepalive_sec")
        );
    }

    #[test]
    fn config_rejects_invalid_seed_and_replacement_limits() {
        let mut cfg = sample_config();
        cfg.dns_seeds = vec!["seed.example.org".to_owned(), "   ".to_owned()];
        let err = cfg.validate().expect_err("empty dns seed must fail");
        assert!(
            err.to_string()
                .contains("dns_seeds must not contain empty entries")
        );

        let mut cfg = sample_config();
        cfg.p2p_replacement_max_per_peer = 0;
        let err = cfg
            .validate()
            .expect_err("replacement max per peer == 0 must fail");
        assert!(
            err.to_string()
                .contains("p2p_replacement_max_per_peer must be > 0")
        );
    }
}
