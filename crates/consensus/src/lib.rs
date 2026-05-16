#![cfg_attr(not(test), deny(clippy::unwrap_used))]
pub mod csv;
pub mod difficulty;
pub mod multisig;
pub mod utxo;
pub mod validate;

pub use csv::{
    LockKind, SEQUENCE_DISABLE_FLAG, SEQUENCE_RESERVED_MASK, SEQUENCE_TIME_GRANULARITY_SHIFT,
    SEQUENCE_TYPE_FLAG, SEQUENCE_VALUE_MASK, SequenceLockError, SequenceLockOutcome,
    check_sequence_lock,
};
pub use difficulty::{asert_next, chainwork_for_target, lwma_next, retarget_next};
pub use multisig::{
    MAX_PARTICIPANTS, MULTISIG_MAX_BLOB, MULTISIG_MIN_BLOB, MULTISIG_TAG, MultisigDescriptor,
    MultisigError, PUBKEY_LEN, SIG_LEN, looks_like_multisig_blob, verify_multisig_spend,
};
pub use utxo::{
    BlockApplyContext, BlockApplySummary, TxValidationError, UtxoEntry, UtxoSet,
    tx_is_final_for_block, validate_and_apply_block, validate_and_apply_block_with_context,
    validate_and_apply_block_with_limits,
};
pub use validate::{BlockSizeLimits, BlockValidationError, validate_block_basic};
