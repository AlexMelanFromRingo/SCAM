use std::collections::HashSet;

use scam_core::{Block, OutPoint, block_meets_pow};
use thiserror::Error;

pub fn validate_block_basic(block: &Block) -> Result<(), BlockValidationError> {
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
}

#[cfg(test)]
mod tests {
    use scam_core::{Block, BlockHeader, Hash256, OutPoint, Target, Transaction, TxIn, TxOut};

    use crate::validate::{BlockValidationError, validate_block_basic};

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

        validate_block_basic(&block).expect("block should be valid");
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

        let err = validate_block_basic(&block).expect_err("should fail");
        assert!(matches!(err, BlockValidationError::MultipleCoinbase));
    }
}
