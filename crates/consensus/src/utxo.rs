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
    /// Block timestamp at the height when this UTXO was created.
    /// Required for BIP68 (CSV) relative-time locktimes. Older redb
    /// databases without this field will fail to deserialize and must
    /// be rebuilt — devnet/testnet only, no live mainnet yet.
    #[serde(default)]
    pub created_time: u64,
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
    validate_and_apply_block_with_context(
        block,
        BlockApplyContext {
            current_height,
            block_subsidy,
            coinbase_maturity,
            chain_domain,
            limits: BlockSizeLimits::UNBOUNDED,
            // When the caller can't supply MTP we fall back to the
            // block header timestamp. This matches the historical
            // SCAM behavior; BIP68 time-locks degrade to "satisfied
            // against header time" instead of MTP.
            median_time_past: None,
        },
        utxos,
    )
}

/// Back-compat wrapper. Prefer [`validate_and_apply_block_with_context`]
/// for new code so MTP and any future per-block parameters can be added
/// without further signature changes.
pub fn validate_and_apply_block_with_limits(
    block: &Block,
    current_height: u64,
    block_subsidy: u64,
    coinbase_maturity: u64,
    chain_domain: &[u8],
    limits: BlockSizeLimits,
    utxos: &mut UtxoSet,
) -> Result<BlockApplySummary, TxValidationError> {
    validate_and_apply_block_with_context(
        block,
        BlockApplyContext {
            current_height,
            block_subsidy,
            coinbase_maturity,
            chain_domain,
            limits,
            median_time_past: None,
        },
        utxos,
    )
}

/// Per-block context shared between the validator and the per-tx
/// machinery. Borrowed-only fields here intentionally (caller owns
/// the storage), so the struct never escapes the call.
#[derive(Clone, Copy, Debug)]
pub struct BlockApplyContext<'a> {
    pub current_height: u64,
    pub block_subsidy: u64,
    pub coinbase_maturity: u64,
    pub chain_domain: &'a [u8],
    pub limits: BlockSizeLimits,
    /// BIP68: time-based sequence locks compare against the MTP
    /// (median-time-past of the prior 11 headers), not the raw
    /// block header timestamp — to make the chain clock monotonic
    /// and resistant to a miner stamping a future-dated header to
    /// unlock funds early. When `None` we fall back to the header
    /// timestamp; chain runtime always supplies the real MTP.
    pub median_time_past: Option<u64>,
}

/// Full-fidelity entry point. Takes a `BlockApplyContext` so new
/// per-block parameters can be added without further breaking the
/// signature; the old `*_with_limits` and bare wrappers remain for
/// callers that don't care.
pub fn validate_and_apply_block_with_context(
    block: &Block,
    ctx: BlockApplyContext<'_>,
    utxos: &mut UtxoSet,
) -> Result<BlockApplySummary, TxValidationError> {
    validate_and_apply_block_with_undo(block, ctx, utxos).map(|(summary, _)| summary)
}

/// Net effect of one connected block on the UTXO set, sufficient to
/// disconnect it again with [`revert_block_undo`].
///
/// `spent_entries` only lists outputs that existed *before* the block;
/// `created_outpoints` only lists outputs that still exist *after* it.
/// Outputs created and spent inside the same block appear in neither.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockUndoData {
    pub spent_entries: Vec<(OutPoint, UtxoEntry)>,
    pub created_outpoints: Vec<OutPoint>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UndoError {
    #[error("cannot disconnect block: created output {outpoint:?} is missing from the UTXO set")]
    MissingCreatedOutput { outpoint: OutPoint },
    #[error("cannot disconnect block: spent output {outpoint:?} is already present")]
    SpentOutputAlreadyPresent { outpoint: OutPoint },
}

/// Disconnect a block previously connected with
/// [`validate_and_apply_block_with_undo`]. All-or-nothing: on error the
/// set is left untouched.
pub fn revert_block_undo(undo: &BlockUndoData, utxos: &mut UtxoSet) -> Result<(), UndoError> {
    for outpoint in &undo.created_outpoints {
        if !utxos.contains_key(outpoint) {
            return Err(UndoError::MissingCreatedOutput {
                outpoint: outpoint.clone(),
            });
        }
    }
    let created: HashSet<&OutPoint> = undo.created_outpoints.iter().collect();
    for (outpoint, _) in &undo.spent_entries {
        if utxos.contains_key(outpoint) && !created.contains(outpoint) {
            return Err(UndoError::SpentOutputAlreadyPresent {
                outpoint: outpoint.clone(),
            });
        }
    }
    for outpoint in &undo.created_outpoints {
        utxos.remove(outpoint);
    }
    for (outpoint, entry) in &undo.spent_entries {
        utxos.insert(outpoint.clone(), entry.clone());
    }
    Ok(())
}

/// Validate `block` against `utxos` and, only if every rule passes,
/// apply it. Returns the undo record for a later disconnect.
///
/// The set is never cloned: outputs created inside the block live in a
/// per-block overlay and the base set is mutated once, at the end, after
/// all checks succeeded. A failed block leaves `utxos` untouched.
pub fn validate_and_apply_block_with_undo(
    block: &Block,
    ctx: BlockApplyContext<'_>,
    utxos: &mut UtxoSet,
) -> Result<(BlockApplySummary, BlockUndoData), TxValidationError> {
    validate_block_basic(block, ctx.limits).map_err(TxValidationError::InvalidBlockStructure)?;
    if !block_meets_pow(block) {
        return Err(TxValidationError::PowMismatch);
    }

    let coinbase = &block.transactions[0];
    let coinbase_value = tx_output_total(coinbase);

    let mut overlay = BlockOverlay {
        base: utxos,
        spent: HashSet::new(),
        created: HashMap::new(),
        created_height: ctx.current_height,
        created_time: block.header.timestamp,
    };
    let mut total_fees: u128 = 0;
    let mut spent_count = 0usize;
    let mut created_count = 0usize;

    let csv_time = ctx.median_time_past.unwrap_or(block.header.timestamp);

    for (tx_index, tx) in block.transactions.iter().enumerate().skip(1) {
        let (input_total, output_total) = validate_non_coinbase_tx(
            tx,
            tx_index,
            (ctx.current_height, block.header.timestamp, csv_time),
            ctx.coinbase_maturity,
            ctx.chain_domain,
            &mut overlay.spent,
            |outpoint| {
                overlay
                    .created
                    .get(outpoint)
                    .or_else(|| overlay.base.get(outpoint))
                    .cloned()
            },
        )?;

        let fee = input_total
            .checked_sub(output_total)
            .ok_or(TxValidationError::NegativeFee { tx_index })?;
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(TxValidationError::FeeOverflow { tx_index })?;
        spent_count += tx.inputs.len();

        overlay.stage_outputs(tx, tx_index, false)?;
        created_count += tx.outputs.len();
    }

    let max_coinbase_value = (ctx.block_subsidy as u128)
        .checked_add(total_fees)
        .ok_or(TxValidationError::CoinbaseRewardOverflow)?;
    if coinbase_value > max_coinbase_value {
        return Err(TxValidationError::CoinbaseRewardTooHigh {
            allowed: max_coinbase_value,
            got: coinbase_value,
        });
    }

    overlay.stage_outputs(coinbase, 0, true)?;
    created_count += coinbase.outputs.len();

    // Commit. Every check passed, so from here on nothing can fail.
    let BlockOverlay {
        spent, mut created, ..
    } = overlay;
    let mut undo = BlockUndoData::default();
    for outpoint in spent {
        if created.remove(&outpoint).is_none()
            && let Some(entry) = utxos.remove(&outpoint)
        {
            undo.spent_entries.push((outpoint, entry));
        }
    }
    undo.created_outpoints.reserve(created.len());
    for (outpoint, entry) in created {
        undo.created_outpoints.push(outpoint.clone());
        utxos.insert(outpoint, entry);
    }

    Ok((
        BlockApplySummary {
            block_hash: block.header.block_hash(),
            tx_count: block.transactions.len(),
            spent_utxos: spent_count,
            created_utxos: created_count,
            total_fees,
            coinbase_value,
        },
        undo,
    ))
}

/// Per-block view over the base UTXO set: outputs created inside the
/// block live in `created`, outpoints spent inside the block in `spent`.
/// The base set is only read until the block has fully validated.
struct BlockOverlay<'a> {
    base: &'a UtxoSet,
    spent: HashSet<OutPoint>,
    created: HashMap<OutPoint, UtxoEntry>,
    created_height: u64,
    created_time: u64,
}

impl BlockOverlay<'_> {
    /// Stage `tx`'s outputs, enforcing the BIP30 rule: a block may not
    /// create an outpoint that is currently unspent.
    fn stage_outputs(
        &mut self,
        tx: &Transaction,
        tx_index: usize,
        is_coinbase: bool,
    ) -> Result<(), TxValidationError> {
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            let live_in_base = self.base.contains_key(&outpoint) && !self.spent.contains(&outpoint);
            if live_in_base || self.created.contains_key(&outpoint) {
                return Err(TxValidationError::OutputAlreadyExists { tx_index, outpoint });
            }
            self.created.insert(
                outpoint,
                UtxoEntry {
                    value: output.value,
                    key_hash20: output.key_hash20,
                    created_height: self.created_height,
                    created_time: self.created_time,
                    is_coinbase,
                },
            );
        }
        Ok(())
    }
}

/// Chain context for validating a transaction that is not in a block yet
/// (mempool admission, block-template assembly): "would this tx be valid in
/// the next block on top of the current tip?".
#[derive(Clone, Copy, Debug)]
pub struct NextBlockTxContext<'a> {
    /// Height of the block the tx would be mined in (`tip_height + 1`).
    pub next_height: u64,
    /// Median-time-past of the current tip. The next header must carry a
    /// timestamp strictly greater than this, so `median_time_past + 1` is the
    /// most conservative clock for absolute lock_time, and it is the BIP68
    /// clock for relative time locks.
    pub median_time_past: u64,
    pub coinbase_maturity: u64,
    pub chain_domain: &'a [u8],
    pub max_tx_bytes: Option<usize>,
}

/// Amounts of a transaction that passed [`validate_tx_for_next_block`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedTx {
    pub input_total: u128,
    pub output_total: u128,
    pub fee: u64,
}

/// Full contextual validation of a standalone transaction against the
/// UTXO view returned by `lookup` — the same per-input rules a block applies
/// (ownership, signatures incl. multisig, coinbase maturity, absolute and
/// BIP68 relative locks, value overflow). Outputs of unconfirmed parents
/// should be returned with `created_height = next_height` and
/// `created_time = median_time_past`, which makes any non-zero relative lock
/// on them unsatisfiable, as in BIP68.
pub fn validate_tx_for_next_block(
    tx: &Transaction,
    ctx: &NextBlockTxContext<'_>,
    lookup: impl Fn(&OutPoint) -> Option<UtxoEntry>,
) -> Result<ValidatedTx, TxValidationError> {
    const TX_INDEX: usize = 0;
    if tx.inputs.is_empty() {
        return Err(TxValidationError::InvalidBlockStructure(
            BlockValidationError::TxHasNoInputs { tx_index: TX_INDEX },
        ));
    }
    if tx.outputs.is_empty() {
        return Err(TxValidationError::InvalidBlockStructure(
            BlockValidationError::TxHasNoOutputs { tx_index: TX_INDEX },
        ));
    }
    if tx.outputs.iter().any(|out| out.value == 0) {
        return Err(TxValidationError::InvalidBlockStructure(
            BlockValidationError::ZeroValueOutput { tx_index: TX_INDEX },
        ));
    }
    if let Some(max_tx) = ctx.max_tx_bytes {
        let bytes = tx.encode_for_hash().len();
        if bytes > max_tx {
            return Err(TxValidationError::InvalidBlockStructure(
                BlockValidationError::TxTooLarge {
                    tx_index: TX_INDEX,
                    bytes,
                    max_bytes: max_tx,
                },
            ));
        }
    }
    let mut seen_inputs = HashSet::<OutPoint>::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        if !seen_inputs.insert(input.prev_out.clone()) {
            return Err(TxValidationError::InvalidBlockStructure(
                BlockValidationError::DuplicateInputInTx { tx_index: TX_INDEX },
            ));
        }
    }

    let mut spent = HashSet::new();
    let earliest_header_time = ctx.median_time_past.saturating_add(1);
    let (input_total, output_total) = validate_non_coinbase_tx(
        tx,
        TX_INDEX,
        (ctx.next_height, earliest_header_time, ctx.median_time_past),
        ctx.coinbase_maturity,
        ctx.chain_domain,
        &mut spent,
        lookup,
    )?;
    let fee = u64::try_from(input_total - output_total)
        .map_err(|_| TxValidationError::FeeOverflow { tx_index: TX_INDEX })?;
    Ok(ValidatedTx {
        input_total,
        output_total,
        fee,
    })
}

/// Outcome of [`select_valid_block_transactions`].
#[derive(Debug, Default)]
pub struct BlockTxSelection {
    /// Transactions that are valid in this order, with their exact fees.
    pub accepted: Vec<(Transaction, u64)>,
    pub total_fees: u64,
    pub total_tx_bytes: usize,
    /// Candidates dropped (invalid, conflicting, or over the byte budget).
    pub rejected: Vec<(scam_core::Hash256, String)>,
}

/// Filter an ordered candidate list (parents before children) down to a
/// set that is valid as the non-coinbase part of the next block and fits in
/// `max_total_tx_bytes` (bincode bytes, as counted by the block-size rule). Children of a dropped
/// parent are dropped too, because their inputs are then missing.
pub fn select_valid_block_transactions(
    candidates: &[Transaction],
    ctx: &NextBlockTxContext<'_>,
    base: &UtxoSet,
    max_total_tx_bytes: usize,
) -> BlockTxSelection {
    let mut selection = BlockTxSelection::default();
    let mut created = HashMap::<OutPoint, UtxoEntry>::new();
    let mut spent = HashSet::<OutPoint>::new();
    let mut total_fees: u128 = 0;

    for tx in candidates {
        let txid = tx.txid();
        if tx.is_coinbase() {
            selection.rejected.push((txid, "coinbase".to_owned()));
            continue;
        }
        // Budget in block-serialization bytes: the consensus block-size rule
        // measures `bincode::serialized_size(block)`.
        let bytes = bincode::serialized_size(tx)
            .map(|n| n as usize)
            .unwrap_or(usize::MAX);
        if selection.total_tx_bytes.saturating_add(bytes) > max_total_tx_bytes {
            selection
                .rejected
                .push((txid, "block byte budget exhausted".to_owned()));
            continue;
        }
        if tx
            .inputs
            .iter()
            .any(|input| spent.contains(&input.prev_out))
        {
            selection
                .rejected
                .push((txid, "conflicts with an earlier template tx".to_owned()));
            continue;
        }
        let validated = validate_tx_for_next_block(tx, ctx, |outpoint| {
            created
                .get(outpoint)
                .or_else(|| base.get(outpoint))
                .cloned()
        });
        let validated = match validated {
            Ok(v) => v,
            Err(err) => {
                selection.rejected.push((txid, err.to_string()));
                continue;
            }
        };
        let creates_live_outpoint = (0..tx.outputs.len()).any(|vout| {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            created.contains_key(&outpoint) || base.contains_key(&outpoint)
        });
        if creates_live_outpoint {
            selection
                .rejected
                .push((txid, "creates an already-unspent outpoint".to_owned()));
            continue;
        }
        let Some(next_fees) = total_fees.checked_add(u128::from(validated.fee)) else {
            selection
                .rejected
                .push((txid, "fee total overflow".to_owned()));
            continue;
        };
        if u64::try_from(next_fees).is_err() {
            selection
                .rejected
                .push((txid, "fee total overflow".to_owned()));
            continue;
        }

        for input in &tx.inputs {
            created.remove(&input.prev_out);
            spent.insert(input.prev_out.clone());
        }
        for (vout, output) in tx.outputs.iter().enumerate() {
            created.insert(
                OutPoint {
                    txid,
                    vout: vout as u32,
                },
                UtxoEntry {
                    value: output.value,
                    key_hash20: output.key_hash20,
                    created_height: ctx.next_height,
                    created_time: ctx.median_time_past,
                    is_coinbase: false,
                },
            );
        }
        total_fees = next_fees;
        selection.total_tx_bytes += bytes;
        selection.accepted.push((tx.clone(), validated.fee));
    }
    selection.total_fees = u64::try_from(total_fees).unwrap_or(u64::MAX);
    selection
}

// `block_context = (current_height, raw_block_time, csv_time_clock)`.
// `raw_block_time` is the header timestamp; used by the transaction-level
// `tx_is_final_for_block` BIP65 check. `csv_time_clock` is the BIP68 clock
// for time-based per-input sequence locks — chain runtime passes MTP here,
// fallback wrappers pass `raw_block_time`.
fn validate_non_coinbase_tx(
    tx: &Transaction,
    tx_index: usize,
    block_context: (u64, u64, u64),
    coinbase_maturity: u64,
    chain_domain: &[u8],
    spent_in_block: &mut HashSet<OutPoint>,
    lookup: impl Fn(&OutPoint) -> Option<UtxoEntry>,
) -> Result<(u128, u128), TxValidationError> {
    let (current_height, block_timestamp, csv_time_clock) = block_context;
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

        let utxo = lookup(&input.prev_out).ok_or_else(|| TxValidationError::MissingUtxo {
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

        // BIP68 per-input relative locktime (CSV). Only meaningful when
        // the disable bit is unset AND the value portion is non-zero,
        // so legacy `sequence: 0` and `sequence: u32::MAX` paths are
        // unaffected. See `crate::csv` for the full semantics.
        let csv_value = input.sequence & crate::csv::SEQUENCE_VALUE_MASK;
        if input.sequence & crate::csv::SEQUENCE_DISABLE_FLAG == 0 && csv_value != 0 {
            let outcome = crate::csv::check_sequence_lock(
                input.sequence,
                utxo.created_height,
                utxo.created_time,
                current_height,
                csv_time_clock,
            )
            // SequenceLockError is currently an empty enum (Bitcoin-compat:
            // reserved bits are ignored), so this `match` is total.
            .unwrap_or(crate::csv::SequenceLockOutcome::Disabled);
            if let crate::csv::SequenceLockOutcome::Locked {
                kind,
                required,
                actual,
            } = outcome
            {
                return Err(TxValidationError::SequenceLockNotMet {
                    tx_index,
                    input_index,
                    kind: match kind {
                        crate::csv::LockKind::Height => "height",
                        crate::csv::LockKind::Time => "time",
                    },
                    required,
                    actual,
                });
            }
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
            let derived_hash =
                crate::multisig::MultisigDescriptor::script_hash20(&input.pubkey_compressed);
            if derived_hash != utxo.key_hash20 {
                return Err(TxValidationError::PubkeyHashMismatch {
                    tx_index,
                    input_index,
                });
            }
            crate::multisig::verify_multisig_spend(&descriptor, digest, &input.signature).map_err(
                |source| TxValidationError::InvalidMultisigSpend {
                    tx_index,
                    input_index,
                    source,
                },
            )?;
        } else {
            // Legacy P2PKH path.
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
    #[error("tx #{tx_index} creates output {outpoint:?} which is already unspent (BIP30)")]
    OutputAlreadyExists { tx_index: usize, outpoint: OutPoint },
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
    #[error(
        "tx #{tx_index} input #{input_index} CSV {kind} lock not met: required {required}, actual {actual}"
    )]
    SequenceLockNotMet {
        tx_index: usize,
        input_index: usize,
        kind: &'static str,
        required: u64,
        actual: u64,
    },
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

    /// End-to-end CSV: an output is created in block 0 (genesis) and
    /// the spend in block 1 sets sequence = 2 (require 2 blocks
    /// elapsed → required height 2). spend_height = 1, so the spend
    /// must be rejected with SequenceLockNotMet.
    #[test]
    fn block_with_csv_height_lock_not_met_is_rejected() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([150u8; 32]);
        let (_, receiver_key_hash, _) = key_material([151u8; 32]);

        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis-csv".to_vec(),
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

        // Spend with sequence = 2 → require 2 blocks elapsed (need
        // spend_height > 0+2 = 2). Spending at height 1 must be rejected.
        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: genesis_coinbase.txid(),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: miner_pubkey.to_vec(),
                sequence: 2,
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
                signature: b"b1-csv".to_vec(),
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

        let err = validate_and_apply_block(&block1, 1, 50, 1, chain_domain, &mut utxos)
            .expect_err("CSV lock not met must reject");
        match err {
            TxValidationError::SequenceLockNotMet {
                kind,
                required,
                actual,
                ..
            } => {
                assert_eq!(kind, "height");
                assert_eq!(required, 2);
                assert_eq!(actual, 1);
            }
            other => panic!("expected SequenceLockNotMet, got {other:?}"),
        }
    }

    /// MTP wiring: BIP68 time-based sequence locks must compare against
    /// the supplied `median_time_past`, NOT the block header timestamp.
    /// We construct two `BlockApplyContext`s differing only in MTP and
    /// assert the lock outcome differs accordingly.
    ///
    /// Setup: a UTXO created at `t=1_000_000`, spent with sequence =
    /// TYPE | 1 → require 512s elapsed → required_time = 1_000_512.
    /// Header timestamp at spend is `1_005_000` (would satisfy if used).
    /// Two MTP candidates:
    ///   - MTP = 1_000_400 → still locked (1_000_400 < 1_000_512). Reject.
    ///   - MTP = 1_001_000 → satisfied. Accept.
    ///
    /// The second case proves MTP overrides the header timestamp.
    #[test]
    fn csv_time_lock_compares_against_supplied_mtp_not_header_timestamp() {
        use super::{BlockApplyContext, validate_and_apply_block_with_context};

        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([170u8; 32]);
        let (_, receiver_key_hash, _) = key_material([171u8; 32]);

        // Genesis at t=1_000_000.
        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"g".to_vec(),
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
            1_000_000,
            Target::MAX,
            vec![genesis_coinbase.clone()],
        );
        let mut utxos = UtxoSet::new();
        let ctx_genesis = BlockApplyContext {
            current_height: 0,
            block_subsidy: 50,
            coinbase_maturity: 1,
            chain_domain,
            limits: super::BlockSizeLimits::UNBOUNDED,
            median_time_past: Some(1_000_000),
        };
        validate_and_apply_block_with_context(&genesis, ctx_genesis, &mut utxos)
            .expect("genesis applies");

        // Spend with TIME-typed CSV value=1 → require 512s gap.
        let csv_seq = super::super::csv::SEQUENCE_TYPE_FLAG | 1;
        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: genesis_coinbase.txid(),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: miner_pubkey.to_vec(),
                sequence: csv_seq,
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
        // Block header timestamp set to a value that would satisfy the
        // lock if used (5_000s elapsed > 512s required). We rely on
        // MTP to *correctly* reject when MTP says only 400s elapsed.
        let block1 = make_block(
            genesis.header.block_hash(),
            1_005_000,
            Target::MAX,
            vec![block1_coinbase, spend],
        );

        // Case A: MTP = 1_000_400 (only 400s elapsed) → lock not met
        // even though header timestamp would have satisfied it. This
        // is the BIP68 attack-mitigation: a miner can't stamp a
        // future-dated header to unlock CSV early.
        let mut utxos_a = utxos.clone();
        let ctx_a = BlockApplyContext {
            current_height: 1,
            block_subsidy: 50,
            coinbase_maturity: 1,
            chain_domain,
            limits: super::BlockSizeLimits::UNBOUNDED,
            median_time_past: Some(1_000_400),
        };
        let err = validate_and_apply_block_with_context(&block1, ctx_a, &mut utxos_a)
            .expect_err("MTP=1_000_400 < required_time=1_000_512 must reject");
        match err {
            TxValidationError::SequenceLockNotMet { kind, .. } => assert_eq!(kind, "time"),
            other => panic!("expected SequenceLockNotMet(time), got {other:?}"),
        }

        // Case B: MTP = 1_001_000 (1000s elapsed) → satisfied. Same
        // block, same header timestamp, only the MTP differs.
        let mut utxos_b = utxos.clone();
        let ctx_b = BlockApplyContext {
            current_height: 1,
            block_subsidy: 50,
            coinbase_maturity: 1,
            chain_domain,
            limits: super::BlockSizeLimits::UNBOUNDED,
            median_time_past: Some(1_001_000),
        };
        validate_and_apply_block_with_context(&block1, ctx_b, &mut utxos_b)
            .expect("MTP=1_001_000 > required_time=1_000_512 must accept");
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

        let multisig_blob = crate::multisig::MultisigDescriptor::encode(2, &[pk_a, pk_b, pk_c])
            .expect("encode 2-of-3");
        let multisig_hash20 = crate::multisig::MultisigDescriptor::script_hash20(&multisig_blob);

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
        let applied = validate_and_apply_block(&block1, 1, 100, 1, chain_domain, &mut utxos)
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

        let multisig_blob = crate::multisig::MultisigDescriptor::encode(2, &[pk_a, pk_b, pk_c])
            .expect("encode 2-of-3");
        let multisig_hash20 = crate::multisig::MultisigDescriptor::script_hash20(&multisig_blob);

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

    /// BIP30 class: a coinbase byte-identical to an earlier *unspent*
    /// coinbase has the same txid. Before the fix `staged.insert` silently
    /// overwrote the victim's UTXO (resetting its maturity) and a later
    /// disconnect of the copy deleted the outpoint entirely, so nodes that
    /// reorged diverged from nodes that did not.
    #[test]
    fn block_recreating_unspent_outpoint_is_rejected_and_set_is_untouched() {
        let chain_domain = b"devnet";
        let (_, victim_key_hash, _) = key_material([9u8; 32]);
        let victim_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"same-tag".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: victim_key_hash,
            }],
            lock_time: 0,
        };
        let genesis = make_block(
            Hash256::ZERO,
            100,
            Target::MAX,
            vec![victim_coinbase.clone()],
        );
        let mut utxos = UtxoSet::new();
        validate_and_apply_block(&genesis, 0, 50, 1, chain_domain, &mut utxos)
            .expect("genesis applies");
        let before = utxos.clone();

        let copy = make_block(
            genesis.header.block_hash(),
            200,
            Target::MAX,
            vec![victim_coinbase.clone()],
        );
        let err = validate_and_apply_block(&copy, 1, 50, 1, chain_domain, &mut utxos)
            .expect_err("duplicate unspent outpoint must be rejected");
        match err {
            TxValidationError::OutputAlreadyExists { tx_index, outpoint } => {
                assert_eq!(tx_index, 0);
                assert_eq!(outpoint.txid, victim_coinbase.txid());
            }
            other => panic!("expected OutputAlreadyExists, got {other:?}"),
        }
        assert_eq!(utxos, before, "failed block must not mutate the UTXO set");
    }

    /// A transaction may spend an output created by an earlier transaction
    /// of the same block; the undo record must describe the net effect
    /// (base entries spent + outpoints that survive the block).
    #[test]
    fn in_block_parent_child_spend_applies_and_undo_reverts_exactly() {
        let chain_domain = b"devnet";
        let (miner_pubkey, miner_key_hash, miner_secret) = key_material([12u8; 32]);
        let (_, receiver_key_hash, _) = key_material([13u8; 32]);

        let genesis_coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis-chain".to_vec(),
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
        let before = utxos.clone();

        let mut parent = Transaction {
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
                key_hash20: miner_key_hash,
            }],
            lock_time: 0,
        };
        sign_input(&mut parent, 0, chain_domain, &miner_secret);
        let mut child = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: parent.txid(),
                    vout: 0,
                },
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
        sign_input(&mut child, 0, chain_domain, &miner_secret);
        let coinbase1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"b1-chain".to_vec(),
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
            vec![coinbase1, parent.clone(), child.clone()],
        );
        let ctx = super::BlockApplyContext {
            current_height: 1,
            block_subsidy: 50,
            coinbase_maturity: 1,
            chain_domain,
            limits: crate::BlockSizeLimits::UNBOUNDED,
            median_time_past: None,
        };
        let (summary, undo) = super::validate_and_apply_block_with_undo(&block1, ctx, &mut utxos)
            .expect("in-block chain must apply");
        assert_eq!(summary.total_fees, 10);
        // genesis coinbase spent; parent output created and spent in-block;
        // child output + coinbase output survive.
        assert_eq!(utxos.len(), 2);
        assert!(!utxos.contains_key(&OutPoint {
            txid: parent.txid(),
            vout: 0
        }));
        assert_eq!(undo.spent_entries.len(), 1);
        assert_eq!(undo.created_outpoints.len(), 2);

        super::revert_block_undo(&undo, &mut utxos).expect("undo applies");
        assert_eq!(utxos, before, "undo must restore the pre-block set exactly");
    }

    fn funded_set(key_hash: [u8; 20], value: u64) -> (UtxoSet, OutPoint) {
        let outpoint = OutPoint {
            txid: Hash256([0xab; 32]),
            vout: 0,
        };
        let mut utxos = UtxoSet::new();
        utxos.insert(
            outpoint.clone(),
            super::UtxoEntry {
                value,
                key_hash20: key_hash,
                created_height: 1,
                created_time: 1_000,
                is_coinbase: false,
            },
        );
        (utxos, outpoint)
    }

    fn next_ctx(chain_domain: &[u8]) -> super::NextBlockTxContext<'_> {
        super::NextBlockTxContext {
            next_height: 10,
            median_time_past: 5_000,
            coinbase_maturity: 1,
            chain_domain,
            max_tx_bytes: Some(100_000),
        }
    }

    fn spend(
        prev: OutPoint,
        pubkey: &[u8],
        value: u64,
        to: [u8; 20],
        sequence: u32,
    ) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: prev,
                signature: vec![],
                pubkey_compressed: pubkey.to_vec(),
                sequence,
            }],
            outputs: vec![TxOut {
                value,
                key_hash20: to,
            }],
            lock_time: 0,
        }
    }

    /// M1: a spend with a forged signature (or someone else's key) must be
    /// rejected at admission, not only at block validation.
    #[test]
    fn next_block_validation_rejects_forged_and_foreign_spends() {
        let domain = b"devnet";
        let (owner_pk, owner_hash, owner_sk) = key_material([21u8; 32]);
        let (thief_pk, _, thief_sk) = key_material([22u8; 32]);
        let (utxos, outpoint) = funded_set(owner_hash, 1_000);
        let ctx = next_ctx(domain);
        let lookup = |op: &OutPoint| utxos.get(op).cloned();

        let mut garbage = spend(outpoint.clone(), &owner_pk, 10, owner_hash, u32::MAX);
        garbage.inputs[0].signature = vec![7u8; 64];
        assert!(matches!(
            super::validate_tx_for_next_block(&garbage, &ctx, lookup),
            Err(TxValidationError::InvalidSignature { .. })
        ));

        let mut foreign = spend(outpoint.clone(), &thief_pk, 10, owner_hash, u32::MAX);
        sign_input(&mut foreign, 0, domain, &thief_sk);
        assert!(matches!(
            super::validate_tx_for_next_block(&foreign, &ctx, lookup),
            Err(TxValidationError::PubkeyHashMismatch { .. })
        ));

        let mut honest = spend(outpoint, &owner_pk, 900, owner_hash, u32::MAX);
        sign_input(&mut honest, 0, domain, &owner_sk);
        let ok = super::validate_tx_for_next_block(&honest, &ctx, lookup).expect("valid");
        assert_eq!(ok.fee, 100);
    }

    /// M2: a BIP68 relative lock that is not met at the next block must be
    /// rejected at admission; otherwise it poisons every block template.
    #[test]
    fn next_block_validation_enforces_relative_locks() {
        let domain = b"devnet";
        let (pk, hash, sk) = key_material([23u8; 32]);
        let (utxos, outpoint) = funded_set(hash, 1_000);
        let ctx = next_ctx(domain);
        // Created at height 1, next height 10 ⇒ 9 confirmations available.
        let mut locked = spend(outpoint.clone(), &pk, 900, hash, 50);
        sign_input(&mut locked, 0, domain, &sk);
        assert!(matches!(
            super::validate_tx_for_next_block(&locked, &ctx, |op| utxos.get(op).cloned()),
            Err(TxValidationError::SequenceLockNotMet { .. })
        ));
        // SCAM's CSV rule is `next_height > created_height + value` (one
        // block stricter than BIP68's `>=`), so 8 is the largest lock that
        // is met at height 10 for an output created at height 1.
        let mut mature = spend(outpoint, &pk, 900, hash, 8);
        sign_input(&mut mature, 0, domain, &sk);
        super::validate_tx_for_next_block(&mature, &ctx, |op| utxos.get(op).cloned())
            .expect("an 8-block lock is met at height 10");
    }

    /// M4/M5: template selection keeps parents before children, drops an
    /// invalid tx together with its descendants, and respects the byte budget.
    #[test]
    fn template_selection_drops_invalid_chains_and_respects_byte_budget() {
        let domain = b"devnet";
        let (pk, hash, sk) = key_material([24u8; 32]);
        let (mut utxos, outpoint_a) = funded_set(hash, 1_000);
        let outpoint_b = OutPoint {
            txid: Hash256([0xcd; 32]),
            vout: 0,
        };
        utxos.insert(
            outpoint_b.clone(),
            super::UtxoEntry {
                value: 1_000,
                key_hash20: hash,
                created_height: 1,
                created_time: 1_000,
                is_coinbase: false,
            },
        );
        let ctx = next_ctx(domain);

        let mut parent = spend(outpoint_a, &pk, 990, hash, u32::MAX);
        sign_input(&mut parent, 0, domain, &sk);
        let mut child = spend(
            OutPoint {
                txid: parent.txid(),
                vout: 0,
            },
            &pk,
            980,
            hash,
            u32::MAX,
        );
        sign_input(&mut child, 0, domain, &sk);
        let mut bad = spend(outpoint_b.clone(), &pk, 990, hash, u32::MAX);
        bad.inputs[0].signature = vec![1u8; 64];
        let mut bad_child = spend(
            OutPoint {
                txid: bad.txid(),
                vout: 0,
            },
            &pk,
            900,
            hash,
            u32::MAX,
        );
        sign_input(&mut bad_child, 0, domain, &sk);

        let candidates = vec![parent.clone(), child.clone(), bad, bad_child];
        let all = super::select_valid_block_transactions(&candidates, &ctx, &utxos, usize::MAX);
        assert_eq!(all.accepted.len(), 2);
        assert_eq!(all.accepted[0].0, parent);
        assert_eq!(all.accepted[1].0, child);
        assert_eq!(all.total_fees, 20);
        assert_eq!(all.rejected.len(), 2);

        let one_tx_budget = bincode::serialized_size(&parent).expect("size") as usize;
        let tight =
            super::select_valid_block_transactions(&candidates, &ctx, &utxos, one_tx_budget);
        assert_eq!(tight.accepted.len(), 1);
        assert!(tight.total_tx_bytes <= one_tx_budget);
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
        assert!(super::tx_is_final_for_block(&final_tx, u64::MAX, u64::MAX));
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
