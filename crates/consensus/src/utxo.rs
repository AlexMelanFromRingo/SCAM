use std::collections::{HashMap, HashSet};

use scam_core::{Block, OutPoint, Transaction, TxSigningError, block_meets_pow, hash160_blake3};
use secp256k1::schnorr::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::validate::{BlockSizeLimits, BlockValidationError, validate_block_basic};

/// Threshold (in `tx.lock_time` units) that selects the comparison axis:
/// values below it are block heights, values at-or-above are unix epoch
/// seconds. Matches BIP65 / Bitcoin Core's `LOCKTIME_THRESHOLD` exactly
/// (the original "no real timestamp will ever be below 500M" reasoning,
/// = 1985-11-05 UTC). Exposed so external tooling — wallet UI, RPC
/// payload formatters — can label a lock_time correctly without
/// reimplementing the split.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

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
    validate_and_apply_block_with_limits(
        block,
        current_height,
        block_subsidy,
        coinbase_maturity,
        chain_domain,
        BlockSizeLimits::UNBOUNDED,
        utxos,
    )
}

/// Same as [`validate_and_apply_block`] but enforces the consensus-level
/// block/tx size caps. Prefer this variant on hot paths; the unbounded
/// wrapper exists so unit tests that pre-date the size enforcement keep
/// compiling.
pub fn validate_and_apply_block_with_limits(
    block: &Block,
    current_height: u64,
    block_subsidy: u64,
    coinbase_maturity: u64,
    chain_domain: &[u8],
    limits: BlockSizeLimits,
    utxos: &mut UtxoSet,
) -> Result<BlockApplySummary, TxValidationError> {
    validate_block_basic(block, limits).map_err(TxValidationError::InvalidBlockStructure)?;
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
            (current_height, block.header.timestamp),
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
    block_context: (u64, u64),
    coinbase_maturity: u64,
    chain_domain: &[u8],
    spent_in_block: &mut HashSet<OutPoint>,
    utxos: &UtxoSet,
) -> Result<(u128, u128), TxValidationError> {
    let (current_height, block_timestamp) = block_context;
    if tx.is_coinbase() {
        return Err(TxValidationError::UnexpectedCoinbase { tx_index });
    }
    if !tx_is_final_for_block(tx, current_height, block_timestamp) {
        return Err(TxValidationError::NonFinalTransaction {
            tx_index,
            lock_time: tx.lock_time,
            block_height: current_height,
            block_time: block_timestamp,
        });
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

        // Spend-condition dispatch: pure shape-based discrimination on
        // the input's `pubkey_compressed` blob.
        //
        // - Exactly 33 bytes → legacy P2PKH (single Schnorr verify).
        // - Multisig blob shape (tag-prefixed, structured) → k-of-n
        //   multisig verify per `crate::multisig`.
        //
        // No collision risk between the two paths: legacy pubkeys are
        // 33 bytes and start with `0x02` or `0x03`; multisig blobs are
        // ≥ `MULTISIG_MIN_BLOB` (51) bytes and start with the
        // `SCAM-multisig-v1` tag. The hash commitment in
        // `utxo.key_hash20` is computed from whichever blob the spender
        // supplies, so a spender cannot satisfy a P2PKH UTXO with a
        // multisig blob (or vice-versa) — the hashes differ.
        let digest = tx
            .signing_digest_with_chain_domain(input_index, chain_domain)
            .map_err(|source| TxValidationError::SigningDigest { tx_index, source })?;

        if crate::multisig::looks_like_multisig_blob(&input.pubkey_compressed) {
            let descriptor = crate::multisig::MultisigDescriptor::parse(&input.pubkey_compressed)
                .map_err(|source| TxValidationError::InvalidMultisigBlob {
                    tx_index,
                    input_index,
                    source,
                })?;
            let derived_hash = crate::multisig::MultisigDescriptor::script_hash20(
                &input.pubkey_compressed,
            );
            if derived_hash != utxo.key_hash20 {
                return Err(TxValidationError::PubkeyHashMismatch {
                    tx_index,
                    input_index,
                });
            }
            crate::multisig::verify_multisig_spend(&descriptor, digest, &input.signature)
                .map_err(|source| TxValidationError::InvalidMultisigSpend {
                    tx_index,
                    input_index,
                    source,
                })?;
        } else {
            // Legacy P2PKH path.
            let parsed_pubkey =
                PublicKey::from_slice(&input.pubkey_compressed).map_err(|_| {
                    TxValidationError::InvalidPubkey {
                        tx_index,
                        input_index,
                    }
                })?;
            let derived_hash = key_hash20_from_pubkey(input.pubkey_compressed.as_slice())
                .ok_or(TxValidationError::InvalidPubkey {
                    tx_index,
                    input_index,
                })?;
            if derived_hash != utxo.key_hash20 {
                return Err(TxValidationError::PubkeyHashMismatch {
                    tx_index,
                    input_index,
                });
            }
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

/// BIP65-equivalent transaction-level absolute lock check.
///
/// Behavior (matches the BIP65 CLTV "transaction is final" rule used in
/// Bitcoin Core's `IsFinalTx`):
///
/// - `tx.lock_time == 0`     → always final (no lock).
/// - All inputs have `sequence == u32::MAX` → always final (the
///   sequence-final-bypass). Setting any input sequence below MAX
///   activates the lock_time check.
/// - Otherwise: split on [`LOCKTIME_THRESHOLD`] —
///   - `lock_time <  THRESHOLD` → treated as a block height; final iff
///     `lock_time <= block_height`.
///   - `lock_time >= THRESHOLD` → treated as unix seconds; final iff
///     `lock_time <= block_time`.
///
/// Note: SCAM does not have an on-chain script VM, so there is no
/// per-output CLTV opcode. The existing semantics covers the
/// transaction-level case; per-input relative locktime (BIP68 / CSV)
/// is queued for a versionbits-gated follow-up — see
/// `docs/PROTOCOL_DESIGN.md` §3.
pub fn tx_is_final_for_block(tx: &Transaction, block_height: u64, block_time: u64) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    let all_inputs_final = tx.inputs.iter().all(|input| input.sequence == u32::MAX);
    if all_inputs_final {
        return true;
    }
    if tx.lock_time < LOCKTIME_THRESHOLD {
        (tx.lock_time as u64) <= block_height
    } else {
        (tx.lock_time as u64) <= block_time
    }
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
    #[error(
        "tx #{tx_index} is non-final at height={block_height} time={block_time} lock_time={lock_time}"
    )]
    NonFinalTransaction {
        tx_index: usize,
        lock_time: u32,
        block_height: u64,
        block_time: u64,
    },
    #[error("fee overflow in tx #{tx_index}")]
    FeeOverflow { tx_index: usize },
    #[error("coinbase reward overflow")]
    CoinbaseRewardOverflow,
    #[error("coinbase reward too high: allowed {allowed}, got {got}")]
    CoinbaseRewardTooHigh { allowed: u128, got: u128 },
    #[error("multisig blob malformed in tx #{tx_index} input #{input_index}: {source}")]
    InvalidMultisigBlob {
        tx_index: usize,
        input_index: usize,
        source: crate::multisig::MultisigError,
    },
    #[error("multisig spend rejected in tx #{tx_index} input #{input_index}: {source}")]
    InvalidMultisigSpend {
        tx_index: usize,
        input_index: usize,
        source: crate::multisig::MultisigError,
    },
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

    /// End-to-end: 2-of-3 multisig output funded by genesis, spent in
    /// block 1 with two of three signatures. Exercises the new dispatch
    /// in `validate_non_coinbase_tx` against the full apply pipeline.
    #[test]
    fn block_with_2_of_3_multisig_spend_applies() {
        let chain_domain = b"devnet";
        let (pk_a, _ph_a, sk_a) = key_material([100u8; 32]);
        let (pk_b, _ph_b, _sk_b) = key_material([101u8; 32]);
        let (pk_c, _ph_c, sk_c) = key_material([102u8; 32]);
        let (_, receiver_key_hash, _) = key_material([103u8; 32]);

        let multisig_blob =
            crate::multisig::MultisigDescriptor::encode(2, &[pk_a, pk_b, pk_c])
                .expect("encode 2-of-3");
        let multisig_hash20 =
            crate::multisig::MultisigDescriptor::script_hash20(&multisig_blob);

        // Genesis funds the multisig hash (via a coinbase output).
        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis-multisig-fund".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 100,
                key_hash20: multisig_hash20,
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
        validate_and_apply_block(&genesis, 0, 100, 1, chain_domain, &mut utxos)
            .expect("genesis applies");
        assert_eq!(utxos.len(), 1);

        // Spend the multisig output with A + C (2-of-3).
        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: genesis_coinbase.txid(),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: multisig_blob.clone(),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 90,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        // Compute the per-input sighash and sign it with sk_a and sk_c.
        let digest = spend
            .signing_digest_with_chain_domain(0, chain_domain)
            .expect("digest");
        let message = Message::from_digest_slice(&digest.0).expect("msg");
        let secp = Secp256k1::new();
        let kp_a = Keypair::from_secret_key(&secp, &sk_a);
        let kp_c = Keypair::from_secret_key(&secp, &sk_c);
        let sig_a = secp.sign_schnorr_no_aux_rand(&message, &kp_a);
        let sig_c = secp.sign_schnorr_no_aux_rand(&message, &kp_c);
        let mut sigs = Vec::with_capacity(128);
        sigs.extend_from_slice(sig_a.as_ref());
        sigs.extend_from_slice(sig_c.as_ref());
        spend.inputs[0].signature = sigs;

        // Coinbase for block 1 sweeps the fee back to receiver.
        let block1_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"b1-multisig-spend".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 110,
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
        let applied =
            validate_and_apply_block(&block1, 1, 100, 1, chain_domain, &mut utxos)
                .expect("multisig-spend block must apply");
        assert_eq!(applied.total_fees, 10);
        // UTXO set: the multisig coin is consumed, two new outputs created.
        assert_eq!(utxos.len(), 2);
    }

    /// Negative: 1-of-3 multisig spend submitted for a 2-of-3 output is
    /// rejected at consensus level with a typed error.
    #[test]
    fn multisig_spend_below_threshold_is_rejected() {
        let chain_domain = b"devnet";
        let (pk_a, _ph_a, sk_a) = key_material([110u8; 32]);
        let (pk_b, _ph_b, _) = key_material([111u8; 32]);
        let (pk_c, _ph_c, _) = key_material([112u8; 32]);
        let (_, receiver_key_hash, _) = key_material([113u8; 32]);

        let multisig_blob =
            crate::multisig::MultisigDescriptor::encode(2, &[pk_a, pk_b, pk_c])
                .expect("encode 2-of-3");
        let multisig_hash20 =
            crate::multisig::MultisigDescriptor::script_hash20(&multisig_blob);

        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis-multisig".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 100,
                key_hash20: multisig_hash20,
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
        validate_and_apply_block(&genesis, 0, 100, 1, chain_domain, &mut utxos)
            .expect("genesis applies");

        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: genesis_coinbase.txid(),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: multisig_blob.clone(),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 90,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        // Sign with A only — k=2 required → BadSignatureLength.
        let digest = spend
            .signing_digest_with_chain_domain(0, chain_domain)
            .expect("digest");
        let message = Message::from_digest_slice(&digest.0).expect("msg");
        let secp = Secp256k1::new();
        let kp_a = Keypair::from_secret_key(&secp, &sk_a);
        let sig_a = secp.sign_schnorr_no_aux_rand(&message, &kp_a);
        spend.inputs[0].signature = sig_a.as_ref().to_vec();

        let block1_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"b1".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 110,
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
        let err = validate_and_apply_block(&block1, 1, 100, 1, chain_domain, &mut utxos)
            .expect_err("under-threshold spend must reject");
        match err {
            TxValidationError::InvalidMultisigSpend { source, .. } => {
                assert!(matches!(
                    source,
                    crate::multisig::MultisigError::BadSignatureLength { .. }
                ));
            }
            other => panic!("expected InvalidMultisigSpend, got {other:?}"),
        }
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
        match err {
            TxValidationError::ImmatureCoinbaseSpend {
                spend_height,
                mature_height,
                ..
            } => {
                assert_eq!(spend_height, 1);
                assert_eq!(mature_height, 10);
            }
            other => panic!("expected ImmatureCoinbaseSpend, got {other:?}"),
        }
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

    #[test]
    fn block_summary_tracks_spent_and_created_counts_exactly() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([101u8; 32]);
        let (_, receiver_key_hash, _) = key_material([102u8; 32]);

        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![
                TxOut {
                    value: 30,
                    key_hash20: miner_key_hash,
                },
                TxOut {
                    value: 20,
                    key_hash20: miner_key_hash,
                },
            ],
            lock_time: 0,
        };
        let genesis = make_block(
            Hash256::ZERO,
            100,
            Target::MAX,
            vec![genesis_coinbase.clone()],
        );
        let mut utxos = UtxoSet::new();
        validate_and_apply_block(&genesis, 0, 50, 1, chain_domain, &mut utxos)
            .expect("genesis applies");

        let mut spend = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: OutPoint {
                        txid: genesis_coinbase.txid(),
                        vout: 0,
                    },
                    signature: vec![],
                    pubkey_compressed: miner_pubkey.to_vec(),
                    sequence: 0,
                },
                TxIn {
                    prev_out: OutPoint {
                        txid: genesis_coinbase.txid(),
                        vout: 1,
                    },
                    signature: vec![],
                    pubkey_compressed: miner_pubkey.to_vec(),
                    sequence: 0,
                },
            ],
            outputs: vec![TxOut {
                value: 45,
                key_hash20: receiver_key_hash,
            }],
            lock_time: 0,
        };
        sign_input(&mut spend, 0, chain_domain, &miner_secret);
        sign_input(&mut spend, 1, chain_domain, &miner_secret);

        let block1_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"b1".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 55,
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

        let summary = validate_and_apply_block(&block1, 1, 50, 1, chain_domain, &mut utxos)
            .expect("block applies");
        assert_eq!(summary.tx_count, 2);
        assert_eq!(summary.spent_utxos, 2);
        assert_eq!(summary.created_utxos, 2);
        assert_eq!(summary.total_fees, 5);
        assert_eq!(summary.coinbase_value, 55);
    }

    #[test]
    fn coinbase_reward_above_subsidy_plus_fees_is_rejected() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([111u8; 32]);
        let (_, receiver_key_hash, _) = key_material([112u8; 32]);

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
        validate_and_apply_block(&genesis, 0, 50, 1, chain_domain, &mut utxos)
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
                value: 45,
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
                value: 56,
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

        let err = validate_and_apply_block(&block1, 1, 50, 1, chain_domain, &mut utxos)
            .expect_err("coinbase above subsidy + fees must fail");
        match err {
            TxValidationError::CoinbaseRewardTooHigh { allowed, got } => {
                assert_eq!(allowed, 55);
                assert_eq!(got, 56);
            }
            other => panic!("expected CoinbaseRewardTooHigh, got {other:?}"),
        }
    }

    #[test]
    fn zero_fee_spend_is_valid() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([121u8; 32]);
        let (_, receiver_key_hash, _) = key_material([122u8; 32]);

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
        validate_and_apply_block(&genesis, 0, 50, 1, chain_domain, &mut utxos)
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
                value: 50,
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
                value: 50,
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

        let summary = validate_and_apply_block(&block1, 1, 50, 1, chain_domain, &mut utxos)
            .expect("zero-fee spend should pass");
        assert_eq!(summary.total_fees, 0);
        assert_eq!(summary.coinbase_value, 50);
    }

    #[test]
    fn non_final_transaction_is_rejected_when_lock_time_not_reached() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([131u8; 32]);
        let (_, receiver_key_hash, _) = key_material([132u8; 32]);

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
        validate_and_apply_block(&genesis, 0, 50, 1, chain_domain, &mut utxos)
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
            lock_time: 2,
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

        let err = validate_and_apply_block(&block1, 1, 50, 1, chain_domain, &mut utxos)
            .expect_err("non-final tx must be rejected");
        assert!(matches!(err, TxValidationError::NonFinalTransaction { .. }));
    }

    #[test]
    fn final_sequence_disables_lock_time_enforcement() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([141u8; 32]);
        let (_, receiver_key_hash, _) = key_material([142u8; 32]);

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
        validate_and_apply_block(&genesis, 0, 50, 1, chain_domain, &mut utxos)
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
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 49,
                key_hash20: receiver_key_hash,
            }],
            lock_time: u32::MAX,
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

        let summary = validate_and_apply_block(&block1, 1, 50, 1, chain_domain, &mut utxos)
            .expect("final sequence should allow lock_time bypass");
        assert_eq!(summary.total_fees, 1);
    }

    #[test]
    fn tx_is_final_for_block_supports_height_and_time_thresholds() {
        let tx_height_locked = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([0x22; 32]),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: vec![0x02; 33],
                sequence: 1,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [0x33; 20],
            }],
            lock_time: 10,
        };
        assert!(!super::tx_is_final_for_block(
            &tx_height_locked,
            9,
            1_000_000
        ));
        assert!(super::tx_is_final_for_block(
            &tx_height_locked,
            10,
            1_000_000
        ));

        let tx_time_locked = Transaction {
            lock_time: 500_000_010,
            ..tx_height_locked.clone()
        };
        assert!(!super::tx_is_final_for_block(
            &tx_time_locked,
            1_000,
            500_000_009
        ));
        assert!(super::tx_is_final_for_block(
            &tx_time_locked,
            1_000,
            500_000_010
        ));

        let tx_threshold_locked = Transaction {
            lock_time: super::LOCKTIME_THRESHOLD,
            ..tx_height_locked
        };
        assert!(
            !super::tx_is_final_for_block(
                &tx_threshold_locked,
                (super::LOCKTIME_THRESHOLD as u64).saturating_add(10_000),
                (super::LOCKTIME_THRESHOLD as u64).saturating_sub(1)
            ),
            "lock_time at threshold must use time-based finality, not height-based"
        );
    }

    /// BIP65: sequence-final-bypass. If ALL inputs have sequence ==
    /// u32::MAX, the tx is final regardless of lock_time. This is the
    /// rule that lets a non-time-locked tx coexist with a non-zero
    /// lock_time (legacy compatibility surface).
    #[test]
    fn tx_is_final_when_all_sequences_are_max_even_with_future_locktime() {
        let final_tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: OutPoint {
                        txid: Hash256([0x44; 32]),
                        vout: 0,
                    },
                    signature: vec![],
                    pubkey_compressed: vec![0x02; 33],
                    sequence: u32::MAX,
                },
                TxIn {
                    prev_out: OutPoint {
                        txid: Hash256([0x55; 32]),
                        vout: 1,
                    },
                    signature: vec![],
                    pubkey_compressed: vec![0x03; 33],
                    sequence: u32::MAX,
                },
            ],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [0x66; 20],
            }],
            // Far-future lock_time; bypass must still kick in.
            lock_time: u32::MAX,
        };
        assert!(super::tx_is_final_for_block(&final_tx, 0, 0));
        assert!(super::tx_is_final_for_block(
            &final_tx,
            u64::MAX,
            u64::MAX
        ));
    }

    /// BIP65: ANY single non-MAX sequence activates the lock_time check.
    /// This is the rule attackers used to "look final" without being
    /// final pre-fix.
    #[test]
    fn tx_is_not_final_when_any_input_sequence_below_max() {
        let mostly_final = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: OutPoint {
                        txid: Hash256([0x77; 32]),
                        vout: 0,
                    },
                    signature: vec![],
                    pubkey_compressed: vec![0x02; 33],
                    sequence: u32::MAX,
                },
                TxIn {
                    prev_out: OutPoint {
                        txid: Hash256([0x88; 32]),
                        vout: 0,
                    },
                    signature: vec![],
                    pubkey_compressed: vec![0x03; 33],
                    // One input below MAX → bypass not engaged.
                    sequence: u32::MAX - 1,
                },
            ],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [0x99; 20],
            }],
            lock_time: 100,
        };
        assert!(!super::tx_is_final_for_block(&mostly_final, 99, 0));
        assert!(super::tx_is_final_for_block(&mostly_final, 100, 0));
    }

    /// Edge: `lock_time == THRESHOLD - 1` is height-based by spec.
    #[test]
    fn tx_lock_time_one_below_threshold_uses_height_axis() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([0xaa; 32]),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: vec![0x02; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [0xbb; 20],
            }],
            lock_time: super::LOCKTIME_THRESHOLD - 1,
        };
        // height-based: huge block_time must not satisfy it.
        assert!(!super::tx_is_final_for_block(
            &tx,
            (super::LOCKTIME_THRESHOLD as u64) - 2,
            u64::MAX
        ));
        // exact height equality must satisfy it.
        assert!(super::tx_is_final_for_block(
            &tx,
            (super::LOCKTIME_THRESHOLD as u64) - 1,
            0
        ));
    }
}
