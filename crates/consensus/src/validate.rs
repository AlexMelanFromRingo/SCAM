use std::collections::HashSet;

use scam_core::{Block, Hash256, OutPoint, block_meets_pow};
use thiserror::Error;

/// Consensus size limits applied to a block at validation time.
///
/// Sourced from `ChainConfig`. These are *consensus* rules — every node must
/// enforce identical numbers or the network forks. `None` disables a check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockSizeLimits {
    pub max_block_bytes: Option<usize>,
    pub max_tx_bytes: Option<usize>,
}

impl BlockSizeLimits {
    /// Test/debug helper: disable both checks. Production callers should
    /// always derive from `ChainConfig`.
    pub const UNBOUNDED: Self = Self {
        max_block_bytes: None,
        max_tx_bytes: None,
    };

    pub fn from_chain_config(cfg: &scam_core::ChainConfig) -> Self {
        Self {
            max_block_bytes: Some(cfg.max_block_size as usize),
            max_tx_bytes: Some(cfg.max_tx_size as usize),
        }
    }
}

pub fn validate_block_basic(
    block: &Block,
    limits: BlockSizeLimits,
) -> Result<(), BlockValidationError> {
    if block.transactions.is_empty() {
        return Err(BlockValidationError::EmptyBlock);
    }
    if !block.transactions[0].is_coinbase() {
        return Err(BlockValidationError::FirstTxMustBeCoinbase);
    }
    if block.transactions.iter().skip(1).any(|tx| tx.is_coinbase()) {
        return Err(BlockValidationError::MultipleCoinbase);
    }
    if !block.has_valid_merkle_root() {
        return Err(BlockValidationError::InvalidMerkleRoot);
    }
    if !block_meets_pow(block) {
        return Err(BlockValidationError::InvalidPow);
    }

    // F-2 (CVE-2012-2459 class): reject blocks containing the same txid more
    // than once. Bitcoin's merkle algorithm — which we share — can produce the
    // same root for `[a, b, c]` and `[a, b, c, c]`; the cheapest watertight
    // defense is to forbid duplicate txids in the block's tx list.
    let mut seen_txids = HashSet::<Hash256>::with_capacity(block.transactions.len());
    for (idx, tx) in block.transactions.iter().enumerate() {
        if !seen_txids.insert(tx.txid()) {
            return Err(BlockValidationError::DuplicateTxInBlock { tx_index: idx });
        }
    }

    // F-3: per-tx size cap.
    if let Some(max_tx) = limits.max_tx_bytes {
        for (idx, tx) in block.transactions.iter().enumerate() {
            let size = tx.encode_for_hash().len();
            if size > max_tx {
                return Err(BlockValidationError::TxTooLarge {
                    tx_index: idx,
                    bytes: size,
                    max_bytes: max_tx,
                });
            }
        }
    }

    // F-3: whole-block size cap. We compute the canonical serialized size from
    // the same encoder used on the wire (`bincode`) so the limit is
    // wire-equivalent, not implementation-dependent.
    if let Some(max_block) = limits.max_block_bytes {
        let bytes = bincode::serialized_size(block)
            .map(|n| n as usize)
            .unwrap_or(usize::MAX);
        if bytes > max_block {
            return Err(BlockValidationError::BlockTooLarge {
                bytes,
                max_bytes: max_block,
            });
        }
    }

    for (idx, tx) in block.transactions.iter().enumerate() {
        if tx.inputs.is_empty() {
            return Err(BlockValidationError::TxHasNoInputs { tx_index: idx });
        }
        if tx.outputs.is_empty() {
            return Err(BlockValidationError::TxHasNoOutputs { tx_index: idx });
        }
        if tx.outputs.iter().any(|out| out.value == 0) {
            return Err(BlockValidationError::ZeroValueOutput { tx_index: idx });
        }

        // Basic sanity: block-level duplicate input spend is invalid.
        let mut seen_inputs = HashSet::<OutPoint>::new();
        for input in &tx.inputs {
            if !seen_inputs.insert(input.prev_out.clone()) {
                return Err(BlockValidationError::DuplicateInputInTx { tx_index: idx });
            }
        }
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum BlockValidationError {
    #[error("block has no transactions")]
    EmptyBlock,
    #[error("first transaction must be coinbase")]
    FirstTxMustBeCoinbase,
    #[error("only first transaction can be coinbase")]
    MultipleCoinbase,
    #[error("block merkle root is invalid")]
    InvalidMerkleRoot,
    #[error("block does not satisfy PoW target")]
    InvalidPow,
    #[error("transaction #{tx_index} has no inputs")]
    TxHasNoInputs { tx_index: usize },
    #[error("transaction #{tx_index} has no outputs")]
    TxHasNoOutputs { tx_index: usize },
    #[error("transaction #{tx_index} has zero-value output")]
    ZeroValueOutput { tx_index: usize },
    #[error("transaction #{tx_index} has duplicate inputs")]
    DuplicateInputInTx { tx_index: usize },
    #[error("transaction #{tx_index} duplicates an earlier txid in the same block")]
    DuplicateTxInBlock { tx_index: usize },
    #[error("transaction #{tx_index} is {bytes} bytes, exceeds consensus cap of {max_bytes} bytes")]
    TxTooLarge {
        tx_index: usize,
        bytes: usize,
        max_bytes: usize,
    },
    #[error("block is {bytes} bytes, exceeds consensus cap of {max_bytes} bytes")]
    BlockTooLarge { bytes: usize, max_bytes: usize },
}

#[cfg(test)]
mod tests {
    use scam_core::{Block, BlockHeader, Hash256, OutPoint, Target, Transaction, TxIn, TxOut};

    use crate::validate::{BlockSizeLimits, BlockValidationError, validate_block_basic};

    fn make_coinbase() -> Transaction {
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
                key_hash20: [1u8; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn valid_minimal_block_passes() {
        let coinbase = make_coinbase();
        let merkle = scam_core::merkle::merkle_root(&[coinbase.txid()]);
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: merkle,
                timestamp: 1_770_763_200,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: vec![coinbase],
        };

        validate_block_basic(&block, BlockSizeLimits::UNBOUNDED).expect("block should be valid");
    }

    #[test]
    fn non_first_coinbase_is_rejected() {
        let coinbase = make_coinbase();
        let tx2 = make_coinbase();
        let txids = [coinbase.txid(), tx2.txid()];
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: scam_core::merkle::merkle_root(&txids),
                timestamp: 1_770_763_200,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: vec![coinbase, tx2],
        };

        let err =
            validate_block_basic(&block, BlockSizeLimits::UNBOUNDED).expect_err("should fail");
        assert!(matches!(err, BlockValidationError::MultipleCoinbase));
    }

    /// F-2 (CVE-2012-2459 class). With pre-fix odd-leaf duplication, the
    /// merkle root for `[a, b, c]` equals the root for `[a, b, c, c]`. The
    /// canonical 3-leaf block pads to `[a,b,c,c]` internally; the attacker
    /// propagates the 4-leaf version directly — same root, distinct payload.
    /// Without the new duplicate-txid check the attacker block would pass
    /// `InvalidMerkleRoot` and we'd then rely on input-collision detection
    /// to catch it. The fix rejects the duplicate-txid in the tx list
    /// explicitly so this defense holds even if a future code path relaxes
    /// the input-collision rule.
    #[test]
    fn merkle_duplicate_last_tx_attack_is_rejected() {
        let coinbase = make_coinbase();
        let payload_a = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([0x42; 32]),
                    vout: 0,
                },
                signature: vec![0u8; 64],
                pubkey_compressed: vec![0x02; 33],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [0x11; 20],
            }],
            lock_time: 0,
        };
        let payload_b = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([0x77; 32]),
                    vout: 0,
                },
                signature: vec![0u8; 64],
                pubkey_compressed: vec![0x03; 33],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 2,
                key_hash20: [0x22; 20],
            }],
            lock_time: 0,
        };
        let canonical_txids = [coinbase.txid(), payload_a.txid(), payload_b.txid()];
        let canonical_root = scam_core::merkle::merkle_root(&canonical_txids);
        let attacker_txids = [
            coinbase.txid(),
            payload_a.txid(),
            payload_b.txid(),
            payload_b.txid(),
        ];
        let attacker_root = scam_core::merkle::merkle_root(&attacker_txids);
        assert_eq!(
            canonical_root, attacker_root,
            "preconditions: pre-fix merkle algorithm must collide"
        );

        let attacker_block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: attacker_root,
                timestamp: 1_770_763_200,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: vec![coinbase, payload_a, payload_b.clone(), payload_b],
        };

        let err = validate_block_basic(&attacker_block, BlockSizeLimits::UNBOUNDED)
            .expect_err("duplicate-txid block must be rejected");
        match err {
            BlockValidationError::DuplicateTxInBlock { tx_index } => assert_eq!(tx_index, 3),
            other => panic!("expected DuplicateTxInBlock, got {other:?}"),
        }
    }

    /// F-3: consensus block-size cap is enforced at validation time, not just
    /// at config-load time. Setting a tiny limit must reject an otherwise
    /// valid block.
    #[test]
    fn oversize_block_is_rejected() {
        let coinbase = make_coinbase();
        let merkle = scam_core::merkle::merkle_root(&[coinbase.txid()]);
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: merkle,
                timestamp: 1_770_763_200,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: vec![coinbase],
        };

        let limits = BlockSizeLimits {
            max_block_bytes: Some(8),
            max_tx_bytes: None,
        };
        let err = validate_block_basic(&block, limits).expect_err("block must be too large");
        match err {
            BlockValidationError::BlockTooLarge { bytes, max_bytes } => {
                assert!(bytes > max_bytes, "expected bytes > max_bytes");
                assert_eq!(max_bytes, 8);
            }
            other => panic!("expected BlockTooLarge, got {other:?}"),
        }
    }

    /// F-3: per-tx size cap. A coinbase with a fat signature blob must be
    /// rejected with a typed error referencing its index.
    #[test]
    fn oversize_tx_is_rejected() {
        let mut coinbase = make_coinbase();
        coinbase.inputs[0].signature = vec![0u8; 10_000];
        let merkle = scam_core::merkle::merkle_root(&[coinbase.txid()]);
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: merkle,
                timestamp: 1_770_763_200,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: vec![coinbase],
        };

        let limits = BlockSizeLimits {
            max_block_bytes: None,
            max_tx_bytes: Some(256),
        };
        let err = validate_block_basic(&block, limits).expect_err("tx must be too large");
        match err {
            BlockValidationError::TxTooLarge { tx_index, .. } => assert_eq!(tx_index, 0),
            other => panic!("expected TxTooLarge, got {other:?}"),
        }
    }
}
