#![cfg_attr(not(test), deny(clippy::unwrap_used))]
pub mod codec;
pub mod config;
pub mod hash;
pub mod merkle;
pub mod pow;
pub mod target;
pub mod types;
pub mod versionbits;
pub mod visual;

pub use config::{ChainConfig, ChainConfigError, DifficultyAlgorithm};
pub use hash::{Hash256, hash160_blake3, hash256, tagged_hash256};
pub use pow::{block_meets_pow, header_meets_pow};
pub use target::Target;
pub use types::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut, TxSigningError};
pub use versionbits::{
    Deployment, DeploymentState, VERSIONBITS_MAX_BIT, VERSIONBITS_TOP_BITS, VERSIONBITS_TOP_MASK,
    deployment_bit_signaled, evaluate_from_history, next_state,
};
pub use visual::{HashBitmap16, render_hash_bitmap_16x16};
