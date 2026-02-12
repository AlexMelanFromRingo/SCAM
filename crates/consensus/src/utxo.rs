use std::collections::{HashMap, HashSet};

use scam_core::{Block, OutPoint, Transaction, TxSigningError, block_meets_pow, hash160_blake3};
use secp256k1::schnorr::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::validate::{BlockValidationError, validate_block_basic};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub value: u64,
    pub key_hash20: [u8; 20],
    pub created_height: u64,
    pub is_coinbase: bool,
}

pub type UtxoSet = HashMap<OutPoint, UtxoEntry>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockApplySummary {
    pub block_hash: scam_core::Hash256,
    pub tx_count: usize,
    pub spent_utxos: usize,
    pub created_utxos: usize,
    pub total_fees: u128,
    pub coinbase_value: u128,
}

pub fn validate_and_apply_block(
    block: &Block,
    current_height: u64,
    block_subsidy: u64,
    coinbase_maturity: u64,
    chain_domain: &[u8],
    utxos: &mut UtxoSet,
) -> Result<BlockApplySummary, TxValidationError> {
    validate_block_basic(block).map_err(TxValidationError::InvalidBlockStructure)?;
    if !block_meets_pow(block) {
        return Err(TxValidationError::PowMismatch);
    }

    let coinbase = &block.transactions[0];
    let coinbase_value = tx_output_total(coinbase);

    let mut staged = utxos.clone();
    let mut spent_in_block = HashSet::<OutPoint>::new();
    let mut total_fees: u128 = 0;
    let mut spent_count = 0usize;
    let mut created_count = 0usize;

    for (tx_index, tx) in block.transactions.iter().enumerate().skip(1) {
        let (input_total, output_total) = validate_non_coinbase_tx(
            tx,
            tx_index,
            current_height,
            coinbase_maturity,
            chain_domain,
            &mut spent_in_block,
            &staged,
        )?;

        let fee = input_total
            .checked_sub(output_total)
            .ok_or(TxValidationError::NegativeFee { tx_index })?;
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(TxValidationError::FeeOverflow { tx_index })?;

        for input in &tx.inputs {
            let removed = staged.remove(&input.prev_out);
            if removed.is_none() {
                return Err(TxValidationError::MissingUtxo {
                    tx_index,
                    outpoint: input.prev_out.clone(),
                });
            }
            spent_count += 1;
        }

        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            staged.insert(
                OutPoint {
                    txid,
                    vout: vout as u32,
                },
                UtxoEntry {
                    value: output.value,
                    key_hash20: output.key_hash20,
                    created_height: current_height,
                    is_coinbase: false,
                },
            );
            created_count += 1;
        }
    }

    let max_coinbase_value = (block_subsidy as u128)
        .checked_add(total_fees)
        .ok_or(TxValidationError::CoinbaseRewardOverflow)?;
    if coinbase_value > max_coinbase_value {
        return Err(TxValidationError::CoinbaseRewardTooHigh {
            allowed: max_coinbase_value,
            got: coinbase_value,
        });
    }

    let coinbase_txid = coinbase.txid();
    for (vout, output) in coinbase.outputs.iter().enumerate() {
        staged.insert(
            OutPoint {
                txid: coinbase_txid,
                vout: vout as u32,
            },
            UtxoEntry {
                value: output.value,
                key_hash20: output.key_hash20,
                created_height: current_height,
                is_coinbase: true,
            },
        );
        created_count += 1;
    }

    *utxos = staged;

    Ok(BlockApplySummary {
        block_hash: block.header.block_hash(),
        tx_count: block.transactions.len(),
        spent_utxos: spent_count,
        created_utxos: created_count,
        total_fees,
        coinbase_value,
    })
}

fn validate_non_coinbase_tx(
    tx: &Transaction,
    tx_index: usize,
    current_height: u64,
    coinbase_maturity: u64,
    chain_domain: &[u8],
    spent_in_block: &mut HashSet<OutPoint>,
    utxos: &UtxoSet,
) -> Result<(u128, u128), TxValidationError> {
    if tx.is_coinbase() {
        return Err(TxValidationError::UnexpectedCoinbase { tx_index });
    }

    let secp = Secp256k1::verification_only();
    let mut input_total: u128 = 0;
    for (input_index, input) in tx.inputs.iter().enumerate() {
        if input.prev_out.is_coinbase() {
            return Err(TxValidationError::CoinbasePrevoutInRegularTx {
                tx_index,
                input_index,
            });
        }

        if !spent_in_block.insert(input.prev_out.clone()) {
            return Err(TxValidationError::DoubleSpendInBlock {
                tx_index,
                outpoint: input.prev_out.clone(),
            });
        }

        let utxo = utxos
            .get(&input.prev_out)
            .ok_or_else(|| TxValidationError::MissingUtxo {
                tx_index,
                outpoint: input.prev_out.clone(),
            })?;

        if utxo.is_coinbase
            && current_height < utxo.created_height.saturating_add(coinbase_maturity)
        {
            return Err(TxValidationError::ImmatureCoinbaseSpend {
                tx_index,
                outpoint: input.prev_out.clone(),
                spend_height: current_height,
                mature_height: utxo.created_height + coinbase_maturity,
            });
        }

        let parsed_pubkey = PublicKey::from_slice(&input.pubkey_compressed).map_err(|_| {
            TxValidationError::InvalidPubkey {
                tx_index,
                input_index,
            }
        })?;
        let derived_hash = key_hash20_from_pubkey(input.pubkey_compressed.as_slice()).ok_or(
            TxValidationError::InvalidPubkey {
                tx_index,
                input_index,
            },
        )?;
        if derived_hash != utxo.key_hash20 {
            return Err(TxValidationError::PubkeyHashMismatch {
                tx_index,
                input_index,
            });
        }

        let digest = tx
            .signing_digest_with_chain_domain(input_index, chain_domain)
            .map_err(|source| TxValidationError::SigningDigest { tx_index, source })?;
        let message = Message::from_digest_slice(&digest.0).map_err(|_| {
            TxValidationError::SigningDigest {
                tx_index,
                source: TxSigningError::InputOutOfBounds {
                    index: input_index,
                    total_inputs: tx.inputs.len(),
                },
            }
        })?;
        let signature = Signature::from_slice(&input.signature).map_err(|_| {
            TxValidationError::InvalidSignatureEncoding {
                tx_index,
                input_index,
            }
        })?;
        let (xonly, _) = parsed_pubkey.x_only_public_key();
        if secp.verify_schnorr(&signature, &message, &xonly).is_err() {
            return Err(TxValidationError::InvalidSignature {
                tx_index,
                input_index,
            });
        }

        input_total = input_total
            .checked_add(utxo.value as u128)
            .ok_or(TxValidationError::InputValueOverflow { tx_index })?;
    }

    let output_total = tx_output_total(tx);
    if input_total < output_total {
        return Err(TxValidationError::Overspend {
            tx_index,
            input_total,
            output_total,
        });
    }

    Ok((input_total, output_total))
}

fn tx_output_total(tx: &Transaction) -> u128 {
    tx.outputs.iter().map(|out| out.value as u128).sum()
}

fn key_hash20_from_pubkey(pubkey_compressed: &[u8]) -> Option<[u8; 20]> {
    if pubkey_compressed.len() != 33 {
        return None;
    }
    Some(hash160_blake3(pubkey_compressed))
}

#[derive(Debug, Error)]
pub enum TxValidationError {
    #[error("invalid block structure: {0}")]
    InvalidBlockStructure(#[from] BlockValidationError),
    #[error("block header hash does not satisfy target")]
    PowMismatch,
    #[error("unexpected coinbase transaction at index {tx_index}")]
    UnexpectedCoinbase { tx_index: usize },
    #[error(
        "regular tx #{tx_index} attempts to spend coinbase null prevout at input #{input_index}"
    )]
    CoinbasePrevoutInRegularTx { tx_index: usize, input_index: usize },
    #[error("tx #{tx_index} references missing utxo {outpoint:?}")]
    MissingUtxo { tx_index: usize, outpoint: OutPoint },
    #[error("tx #{tx_index} double-spends outpoint {outpoint:?} inside block")]
    DoubleSpendInBlock { tx_index: usize, outpoint: OutPoint },
    #[error(
        "coinbase output {outpoint:?} is immature at height {spend_height}; matures at {mature_height}"
    )]
    ImmatureCoinbaseSpend {
        tx_index: usize,
        outpoint: OutPoint,
        spend_height: u64,
        mature_height: u64,
    },
    #[error("invalid pubkey in tx #{tx_index} input #{input_index}")]
    InvalidPubkey { tx_index: usize, input_index: usize },
    #[error("pubkey hash mismatch in tx #{tx_index} input #{input_index}")]
    PubkeyHashMismatch { tx_index: usize, input_index: usize },
    #[error("signing digest error in tx #{tx_index}: {source}")]
    SigningDigest {
        tx_index: usize,
        source: TxSigningError,
    },
    #[error("invalid signature encoding in tx #{tx_index} input #{input_index}")]
    InvalidSignatureEncoding { tx_index: usize, input_index: usize },
    #[error("invalid signature in tx #{tx_index} input #{input_index}")]
    InvalidSignature { tx_index: usize, input_index: usize },
    #[error("input sum overflow in tx #{tx_index}")]
    InputValueOverflow { tx_index: usize },
    #[error("tx #{tx_index} overspends: inputs={input_total}, outputs={output_total}")]
    Overspend {
        tx_index: usize,
        input_total: u128,
        output_total: u128,
    },
    #[error("negative fee in tx #{tx_index}")]
    NegativeFee { tx_index: usize },
    #[error("fee overflow in tx #{tx_index}")]
    FeeOverflow { tx_index: usize },
    #[error("coinbase reward overflow")]
    CoinbaseRewardOverflow,
    #[error("coinbase reward too high: allowed {allowed}, got {got}")]
    CoinbaseRewardTooHigh { allowed: u128, got: u128 },
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

    use super::{TxValidationError, UtxoSet, validate_and_apply_block};
    use scam_core::{Block, BlockHeader, Hash256, OutPoint, Target, Transaction, TxIn, TxOut};

    fn key_material(seed: [u8; 32]) -> ([u8; 33], [u8; 20], SecretKey) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&seed).expect("valid secret");
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret).serialize();
        (pubkey, scam_core::hash160_blake3(&pubkey), secret)
    }

    fn make_block(prev: Hash256, timestamp: u64, target: Target, txs: Vec<Transaction>) -> Block {
        let txids: Vec<Hash256> = txs.iter().map(Transaction::txid).collect();
        let merkle = scam_core::merkle::merkle_root(&txids);
        Block {
            header: BlockHeader {
                version: 1,
                prev_block: prev,
                merkle_root: merkle,
                timestamp,
                target,
                nonce: 0,
            },
            transactions: txs,
        }
    }

    fn sign_input(
        tx: &mut Transaction,
        input_index: usize,
        chain_domain: &[u8],
        secret: &SecretKey,
    ) {
        let digest = tx
            .signing_digest_with_chain_domain(input_index, chain_domain)
            .expect("digest");
        let message = Message::from_digest_slice(&digest.0).expect("msg");
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret);
        let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        tx.inputs[input_index].signature = sig.as_ref().to_vec();
    }

    #[test]
    fn valid_block_with_signed_spend_applies() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([2u8; 32]);
        let (_, receiver_key_hash, _) = key_material([3u8; 32]);

        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: miner_key_hash,
            }],
            lock_time: 0,
        };
        let genesis = make_block(
            Hash256::ZERO,
            100,
            Target::MAX,
            vec![genesis_coinbase.clone()],
        );

        let mut utxos = UtxoSet::new();
        let applied_genesis =
            validate_and_apply_block(&genesis, 0, 50, 1, chain_domain, &mut utxos)
                .expect("genesis must apply");
        assert_eq!(applied_genesis.coinbase_value, 50);
        assert_eq!(utxos.len(), 1);

        let spend_prevout = OutPoint {
            txid: genesis_coinbase.txid(),
            vout: 0,
        };
        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: spend_prevout,
                signature: vec![],
                pubkey_compressed: miner_pubkey.to_vec(),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 40,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        sign_input(&mut spend, 0, chain_domain, &miner_secret);

        let block1_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"b1".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 60,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        let block1 = make_block(
            genesis.header.block_hash(),
            220,
            Target::MAX,
            vec![block1_coinbase, spend],
        );

        let applied = validate_and_apply_block(&block1, 1, 50, 1, chain_domain, &mut utxos)
            .expect("block1 must apply");
        assert_eq!(applied.total_fees, 10);
        assert_eq!(utxos.len(), 2);
    }

    #[test]
    fn immature_coinbase_spend_is_rejected() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([4u8; 32]);
        let (_, receiver_key_hash, _) = key_material([5u8; 32]);

        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: miner_key_hash,
            }],
            lock_time: 0,
        };
        let genesis = make_block(
            Hash256::ZERO,
            100,
            Target::MAX,
            vec![genesis_coinbase.clone()],
        );
        let mut utxos = UtxoSet::new();
        validate_and_apply_block(&genesis, 0, 50, 10, chain_domain, &mut utxos)
            .expect("genesis applies");

        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: genesis_coinbase.txid(),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: miner_pubkey.to_vec(),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 49,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        sign_input(&mut spend, 0, chain_domain, &miner_secret);

        let block1_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"b1".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 51,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        let block1 = make_block(
            genesis.header.block_hash(),
            220,
            Target::MAX,
            vec![block1_coinbase, spend],
        );

        let err = validate_and_apply_block(&block1, 1, 50, 10, chain_domain, &mut utxos)
            .expect_err("reject");
        assert!(matches!(
            err,
            TxValidationError::ImmatureCoinbaseSpend { .. }
        ));
    }

    #[test]
    fn signature_replay_across_chain_domains_is_rejected() {
        let signing_domain = b"devnet";
        let validation_domain = b"mainnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([6u8; 32]);
        let (_, receiver_key_hash, _) = key_material([7u8; 32]);

        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: miner_key_hash,
            }],
            lock_time: 0,
        };
        let genesis = make_block(
            Hash256::ZERO,
            100,
            Target::MAX,
            vec![genesis_coinbase.clone()],
        );
        let mut utxos = UtxoSet::new();
        validate_and_apply_block(&genesis, 0, 50, 1, signing_domain, &mut utxos)
            .expect("genesis applies");

        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: genesis_coinbase.txid(),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: miner_pubkey.to_vec(),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 49,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        sign_input(&mut spend, 0, signing_domain, &miner_secret);

        let block1_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"b1".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 51,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        let block1 = make_block(
            genesis.header.block_hash(),
            220,
            Target::MAX,
            vec![block1_coinbase, spend],
        );

        let err = validate_and_apply_block(&block1, 1, 50, 1, validation_domain, &mut utxos)
            .expect_err("cross-domain replay must fail");
        assert!(matches!(err, TxValidationError::InvalidSignature { .. }));
    }

    proptest! {
        #[test]
        fn self_transfer_with_positive_fee_applies(
            input_value in 2u64..1_000_000u64,
            fee in 1u64..50_000u64,
            key_seed in 1u8..=240u8
        ) {
            prop_assume!(fee < input_value);

            let chain_domain = b"propnet-self";
            let (sender_pubkey, sender_key_hash, sender_secret) = key_material([key_seed; 32]);

            let genesis_coinbase = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_out: OutPoint::coinbase(),
                    signature: b"genesis".to_vec(),
                    pubkey_compressed: vec![],
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOut {
                    value: input_value,
                    key_hash20: sender_key_hash,
                }],
                lock_time: 0,
            };
            let genesis = make_block(
                Hash256::ZERO,
                100,
                Target::MAX,
                vec![genesis_coinbase.clone()],
            );

            let mut utxos = UtxoSet::new();
            validate_and_apply_block(&genesis, 0, input_value, 1, chain_domain, &mut utxos)
                .expect("genesis applies");

            let mut spend = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_out: OutPoint {
                        txid: genesis_coinbase.txid(),
                        vout: 0,
                    },
                    signature: vec![],
                    pubkey_compressed: sender_pubkey.to_vec(),
                    sequence: 0,
                }],
                outputs: vec![TxOut {
                    value: input_value - fee,
                    key_hash20: sender_key_hash,
                }],
                lock_time: 0,
            };
            sign_input(&mut spend, 0, chain_domain, &sender_secret);

            let block1_coinbase = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_out: OutPoint::coinbase(),
                    signature: b"b1".to_vec(),
                    pubkey_compressed: vec![],
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOut {
                    value: input_value + fee,
                    key_hash20: sender_key_hash,
                }],
                lock_time: 0,
            };
            let block1 = make_block(
                genesis.header.block_hash(),
                220,
                Target::MAX,
                vec![block1_coinbase, spend],
            );

            let applied = validate_and_apply_block(
                &block1,
                1,
                input_value,
                1,
                chain_domain,
                &mut utxos,
            )
            .expect("self-transfer spend must be valid");
            prop_assert_eq!(applied.total_fees, fee as u128);
        }

        #[test]
        fn overspend_is_rejected(
            input_value in 1u64..1_000_000u64,
            overspend_delta in 1u64..50_000u64,
            key_seed in 1u8..=240u8,
            receiver_seed in 1u8..=240u8
        ) {
            prop_assume!(key_seed != receiver_seed);
            let chain_domain = b"propnet-overspend";
            let (sender_pubkey, sender_key_hash, sender_secret) = key_material([key_seed; 32]);
            let (_, receiver_key_hash, _) = key_material([receiver_seed; 32]);

            let genesis_coinbase = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_out: OutPoint::coinbase(),
                    signature: b"genesis".to_vec(),
                    pubkey_compressed: vec![],
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOut {
                    value: input_value,
                    key_hash20: sender_key_hash,
                }],
                lock_time: 0,
            };
            let genesis = make_block(
                Hash256::ZERO,
                100,
                Target::MAX,
                vec![genesis_coinbase.clone()],
            );

            let mut utxos = UtxoSet::new();
            validate_and_apply_block(&genesis, 0, input_value, 1, chain_domain, &mut utxos)
                .expect("genesis applies");

            let mut spend = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_out: OutPoint {
                        txid: genesis_coinbase.txid(),
                        vout: 0,
                    },
                    signature: vec![],
                    pubkey_compressed: sender_pubkey.to_vec(),
                    sequence: 0,
                }],
                outputs: vec![TxOut {
                    value: input_value.saturating_add(overspend_delta),
                    key_hash20: receiver_key_hash,
                }],
                lock_time: 0,
            };
            sign_input(&mut spend, 0, chain_domain, &sender_secret);

            let block1_coinbase = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_out: OutPoint::coinbase(),
                    signature: b"b1".to_vec(),
                    pubkey_compressed: vec![],
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOut {
                    value: input_value,
                    key_hash20: receiver_key_hash,
                }],
                lock_time: 0,
            };
            let block1 = make_block(
                genesis.header.block_hash(),
                220,
                Target::MAX,
                vec![block1_coinbase, spend],
            );

            let err = validate_and_apply_block(&block1, 1, input_value, 1, chain_domain, &mut utxos)
                .expect_err("overspend must fail");
            assert!(matches!(err, TxValidationError::Overspend { .. }));
        }
    }
}
