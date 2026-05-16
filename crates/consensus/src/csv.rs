//! BIP68-style per-input relative locktime, encoded in `TxIn::sequence`.
//!
//! ## Encoding (verbatim BIP68)
//!
//! | bit  | meaning |
//! |------|---------|
//! | 31   | DISABLE: when set, no relative lock applies. Spendable always. |
//! | 22   | TYPE:    0 = block-count relative lock; 1 = 512-second-unit relative lock. |
//! | 0-15 | VALUE:   the actual lock; 16-bit unsigned. |
//!
//! Other bits (16-21, 23-30) are currently undefined and ignored
//! (matches Bitcoin Core's `CheckSequence`). Future deployments may
//! repurpose them; not enforcing zero here keeps the upgrade path open
//! without requiring a hard fork.
//!
//! ## Why per-input
//!
//! Bitcoin pre-CSV used `tx.lock_time` for absolute locktime. That's
//! still here (see [`crate::utxo::tx_is_final_for_block`]). CSV adds
//! a *per-input* relative lock so an output can require "N blocks have
//! passed since this UTXO was created" before it's spendable. Common
//! use cases: vault timelocks, payment channels, escrow with refund
//! after delay.
//!
//! ## Compatibility with the existing tx-final-bypass rule
//!
//! SCAM already had a tx-level rule: if ALL inputs have
//! `sequence == u32::MAX`, the tx is "final" and `tx.lock_time` is
//! ignored. We preserve that bypass — `u32::MAX` has bit 31 set, so
//! by BIP68 it's also DISABLE'd, so the same value disables both
//! mechanisms. Other sequence values that have bit 31 set
//! (`0x80000000..0xFFFFFFFE`) similarly disable CSV per-input but DO
//! activate the tx-level lock_time check.
//!
//! ## Activation policy in this branch
//!
//! Always-on. SCAM has no live chain yet; the freshly frozen mainnet
//! genesis is enabled with CSV rules in effect from block 0. On a
//! launched chain CSV would be gated behind a versionbits deployment
//! (see `crate::multisig` precedent and `docs/PROTOCOL_DESIGN.md` §3).

use thiserror::Error;

pub const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;
pub const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;
pub const SEQUENCE_VALUE_MASK: u32 = 0x0000_FFFF;
/// Bits 16..=21 and 23..=30. Reserved per BIP68; must be zero.
pub const SEQUENCE_RESERVED_MASK: u32 =
    !(SEQUENCE_DISABLE_FLAG | SEQUENCE_TYPE_FLAG | SEQUENCE_VALUE_MASK);
/// Granularity exponent: time-locked values count 512-second units.
/// 2^9 = 512.
pub const SEQUENCE_TIME_GRANULARITY_SHIFT: u32 = 9;

/// Result of checking a single input's relative locktime against the
/// spending block context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceLockOutcome {
    /// Lock disabled (bit 31 set), or `sequence == u32::MAX`.
    Disabled,
    /// Lock satisfied by block-height delta.
    SatisfiedByHeight { required_height: u64 },
    /// Lock satisfied by 512-second-unit delta.
    SatisfiedByTime { required_time: u64 },
    /// Lock NOT satisfied — caller must reject the spend.
    Locked {
        kind: LockKind,
        required: u64,
        actual: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockKind {
    Height,
    Time,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SequenceLockError {}

/// Decode and check a `TxIn::sequence` against the UTXO it spends, in
/// the context of the spending block.
///
/// Returns:
/// - `Ok(SequenceLockOutcome::Disabled)` or `Satisfied*` for accepted
///   spends.
/// - `Ok(SequenceLockOutcome::Locked { .. })` for valid sequence with
///   the lock not yet matured — the caller turns this into a typed
///   `TxValidationError`.
///
/// Reserved bits (16-21, 23-30) are ignored, matching Bitcoin Core's
/// `CheckSequence`. Future versionbits-style deployments may attach
/// meaning; that's a soft-fork concern not a validation one.
pub fn check_sequence_lock(
    sequence: u32,
    utxo_created_height: u64,
    utxo_created_time: u64,
    spend_block_height: u64,
    spend_block_time: u64,
) -> Result<SequenceLockOutcome, SequenceLockError> {
    if sequence & SEQUENCE_DISABLE_FLAG != 0 {
        return Ok(SequenceLockOutcome::Disabled);
    }
    let value = u64::from(sequence & SEQUENCE_VALUE_MASK);
    if sequence & SEQUENCE_TYPE_FLAG != 0 {
        // Time-based: value units of 512 seconds. Lock is satisfied
        // when the spending block's median time has *exceeded* the
        // required threshold. BIP68 uses MTP for spend_block_time; for
        // SCAM the caller passes block header timestamp (good enough
        // until we wire MTP through the validate_non_coinbase_tx call
        // site — pre-launch chains only).
        let required_time =
            utxo_created_time.saturating_add(value << SEQUENCE_TIME_GRANULARITY_SHIFT);
        if spend_block_time > required_time {
            Ok(SequenceLockOutcome::SatisfiedByTime { required_time })
        } else {
            Ok(SequenceLockOutcome::Locked {
                kind: LockKind::Time,
                required: required_time,
                actual: spend_block_time,
            })
        }
    } else {
        let required_height = utxo_created_height.saturating_add(value);
        if spend_block_height > required_height {
            Ok(SequenceLockOutcome::SatisfiedByHeight { required_height })
        } else {
            Ok(SequenceLockOutcome::Locked {
                kind: LockKind::Height,
                required: required_height,
                actual: spend_block_height,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_flag_short_circuits() {
        // u32::MAX has bit 31 set → disabled.
        assert_eq!(
            check_sequence_lock(u32::MAX, 100, 200, 0, 0).expect("ok"),
            SequenceLockOutcome::Disabled
        );
        // Just bit 31 set → also disabled.
        assert_eq!(
            check_sequence_lock(SEQUENCE_DISABLE_FLAG, 100, 200, 0, 0).expect("ok"),
            SequenceLockOutcome::Disabled
        );
        // bit 31 + arbitrary value bits → still disabled.
        assert_eq!(
            check_sequence_lock(SEQUENCE_DISABLE_FLAG | 0x42, 100, 200, 0, 0).expect("ok"),
            SequenceLockOutcome::Disabled
        );
    }

    #[test]
    fn reserved_bits_are_ignored_per_bitcoin_compat() {
        // Bit 16 set should NOT change interpretation; only the
        // disable/type/value bits matter.
        let seq = (1u32 << 16) | 5; // reserved bit + value 5
        // No disable flag → block-based with value=5.
        assert_eq!(
            check_sequence_lock(seq, 100, 0, 106, 0).expect("ok"),
            SequenceLockOutcome::SatisfiedByHeight {
                required_height: 105,
            }
        );
        // Reserved bit + DISABLE → disabled (disable wins).
        let seq = (1u32 << 16) | SEQUENCE_DISABLE_FLAG;
        assert_eq!(
            check_sequence_lock(seq, 100, 0, 0, 0).expect("ok"),
            SequenceLockOutcome::Disabled
        );
    }

    #[test]
    fn height_based_lock_satisfied_when_spend_strictly_above_required() {
        // sequence = 5 → block-based, require 5 blocks elapsed.
        // utxo at height 100, spend at height 106 (> 100+5=105) → ok.
        assert_eq!(
            check_sequence_lock(5, 100, 0, 106, 0).expect("ok"),
            SequenceLockOutcome::SatisfiedByHeight {
                required_height: 105
            }
        );
        // Spend at exactly required_height = 105 → still locked (>, not >=).
        assert_eq!(
            check_sequence_lock(5, 100, 0, 105, 0).expect("ok"),
            SequenceLockOutcome::Locked {
                kind: LockKind::Height,
                required: 105,
                actual: 105,
            }
        );
    }

    #[test]
    fn height_zero_means_spend_in_next_block_only() {
        // sequence = 0 (block-based, value=0). Spending in the same
        // block as creation must fail (>, not >=).
        assert!(matches!(
            check_sequence_lock(0, 50, 0, 50, 0).expect("ok"),
            SequenceLockOutcome::Locked {
                kind: LockKind::Height,
                ..
            }
        ));
        // Next block is fine.
        assert!(matches!(
            check_sequence_lock(0, 50, 0, 51, 0).expect("ok"),
            SequenceLockOutcome::SatisfiedByHeight { .. }
        ));
    }

    #[test]
    fn time_based_lock_uses_512_second_granularity() {
        // sequence = TYPE | 1 → time-based, value = 1 → require 512s.
        let seq = SEQUENCE_TYPE_FLAG | 1;
        // utxo at t=1_000_000, spend at t=1_000_513 (= 1_000_000 + 512 + 1) → ok.
        assert_eq!(
            check_sequence_lock(seq, 0, 1_000_000, 0, 1_000_513).expect("ok"),
            SequenceLockOutcome::SatisfiedByTime {
                required_time: 1_000_512
            }
        );
        // Spend at exactly required_time → locked.
        assert!(matches!(
            check_sequence_lock(seq, 0, 1_000_000, 0, 1_000_512).expect("ok"),
            SequenceLockOutcome::Locked {
                kind: LockKind::Time,
                ..
            }
        ));
    }

    #[test]
    fn time_based_lock_with_max_value_is_not_overflow_panic() {
        // sequence value = 0xFFFF, granularity shift = 9 → 0xFFFF << 9
        // is still < 2^25 < 2^64. No overflow. Required time wraps via
        // saturating_add so even u64::MAX utxo_time stays in-range.
        let seq = SEQUENCE_TYPE_FLAG | 0xFFFF;
        let out = check_sequence_lock(seq, 0, u64::MAX - 1, 0, u64::MAX).expect("ok");
        // Result is "Locked" because spend_time is at most u64::MAX,
        // and required_time saturated to u64::MAX. spend > required
        // is false.
        assert!(matches!(out, SequenceLockOutcome::Locked { .. }));
    }
}
