use num_bigint::BigUint;
use num_traits::{One, Zero};
use scam_core::Target;
use thiserror::Error;

pub fn retarget_next(
    old_target: Target,
    actual_timespan_sec: u64,
    expected_timespan_sec: u64,
    clamp_down: f64,
    clamp_up: f64,
    max_target: Target,
) -> Result<Target, DifficultyError> {
    if expected_timespan_sec == 0 {
        return Err(DifficultyError::InvalidExpectedTimespan);
    }
    if clamp_up < 1.0 {
        return Err(DifficultyError::InvalidClamp(
            "clamp_up must be >= 1.0".to_owned(),
        ));
    }
    if clamp_down <= 0.0 || clamp_down > 1.0 {
        return Err(DifficultyError::InvalidClamp(
            "clamp_down must be in (0, 1]".to_owned(),
        ));
    }

    let min_timespan = ((expected_timespan_sec as f64) * clamp_down)
        .round()
        .max(1.0) as u64;
    let max_timespan = ((expected_timespan_sec as f64) * clamp_up)
        .round()
        .max(min_timespan as f64) as u64;
    let clamped_actual = actual_timespan_sec.clamp(min_timespan, max_timespan);

    let old = target_to_biguint(old_target);
    let max = target_to_biguint(max_target);
    let mut next = (old * BigUint::from(clamped_actual)) / BigUint::from(expected_timespan_sec);

    if next.is_zero() {
        next = BigUint::one();
    }
    next = next.min(max);

    biguint_to_target(&next)
}

pub fn chainwork_for_target(target: Target) -> BigUint {
    let target_big = target_to_biguint(target);
    if target_big.is_zero() {
        return BigUint::zero();
    }

    let two_pow_256 = BigUint::one() << 256usize;
    two_pow_256 / (target_big + BigUint::one())
}

pub fn lwma_next(
    recent_targets: &[Target],
    recent_timestamps: &[u64],
    target_block_time_sec: u64,
    max_target: Target,
) -> Result<Target, DifficultyError> {
    if target_block_time_sec == 0 {
        return Err(DifficultyError::InvalidExpectedTimespan);
    }
    if recent_targets.len() < 2 || recent_timestamps.len() < 2 {
        return Err(DifficultyError::InsufficientHistory {
            needed: 2,
            got: recent_targets.len().min(recent_timestamps.len()),
        });
    }
    if recent_targets.len() != recent_timestamps.len() {
        return Err(DifficultyError::InvalidHistoryLayout);
    }

    let n = recent_targets.len() - 1;
    let t = target_block_time_sec as u128;
    let max_solve_time = target_block_time_sec.saturating_mul(6);
    let mut weighted_solvetime_sum = 0u128;
    let mut weighted_target_sum = BigUint::zero();

    // Out-of-sequence timestamps are treated as `previous + 1` and the
    // running "previous" never moves backwards (zawy LWMA-1 handling).
    // Using raw pairwise deltas with a 1-second floor let a miner
    // alternate future/past stamps — `+6T` then `≈0` — and record
    // `6T + 1` for two blocks that took `2T`, ratcheting difficulty down.
    let mut previous_timestamp = recent_timestamps[0];
    for i in 1..=n {
        let this_timestamp = if recent_timestamps[i] > previous_timestamp {
            recent_timestamps[i]
        } else {
            previous_timestamp.saturating_add(1)
        };
        let solve_time = this_timestamp
            .saturating_sub(previous_timestamp)
            .clamp(1, max_solve_time);
        previous_timestamp = this_timestamp;
        let weight = i as u128;
        weighted_solvetime_sum = weighted_solvetime_sum
            .checked_add((solve_time as u128).saturating_mul(weight))
            .ok_or_else(|| {
                DifficultyError::InvalidClamp("lwma weighted solvetime overflow".to_owned())
            })?;
        weighted_target_sum += target_to_biguint(recent_targets[i]);
    }

    let avg_target = weighted_target_sum / BigUint::from(n as u64);
    let k = (n as u128).saturating_mul((n as u128) + 1) / 2;
    let denominator = t.saturating_mul(k).max(1);

    let mut next =
        (avg_target * BigUint::from(weighted_solvetime_sum)) / BigUint::from(denominator);
    if next.is_zero() {
        next = BigUint::one();
    }
    let max = target_to_biguint(max_target);
    next = next.min(max);

    biguint_to_target(&next)
}

pub fn asert_next(
    previous_target: Target,
    observed_solvetime_sec: u64,
    target_block_time_sec: u64,
    half_life_sec: u64,
    max_target: Target,
) -> Result<Target, DifficultyError> {
    if target_block_time_sec == 0 {
        return Err(DifficultyError::InvalidExpectedTimespan);
    }
    if half_life_sec == 0 {
        return Err(DifficultyError::InvalidClamp(
            "asert_half_life_sec must be > 0".to_owned(),
        ));
    }

    // Integer-only fixed-point evaluation (BCH aserti3-2d). Consensus math
    // must not use `f64::powf`: libm implementations differ across
    // platforms, so nodes could disagree on the next target.
    let delta = (observed_solvetime_sec as i128) - (target_block_time_sec as i128);
    let exponent = (delta * 65_536).div_euclid(half_life_sec as i128);
    let shifts = exponent >> 16;
    let frac = (exponent & 0xffff) as u128;
    // 2^(frac/65536) * 65536, approximated by a cubic with < 0.013% error.
    let factor = 65_536u128
        + ((195_766_423_245_049u128 * frac
            + 971_821_376u128 * frac * frac
            + 5_127u128 * frac * frac * frac
            + (1u128 << 47))
            >> 48);

    let max = target_to_biguint(max_target);
    let mut next = target_to_biguint(previous_target) * BigUint::from(factor);
    // Net shift is `shifts - 16`; saturate early so an absurd solvetime
    // cannot make us allocate a huge integer.
    let net_shift = shifts - 16;
    if net_shift >= 256 {
        next = max.clone();
    } else if net_shift >= 0 {
        next <<= net_shift as usize;
    } else if net_shift <= -(256 + 64) {
        next = BigUint::zero();
    } else {
        next >>= (-net_shift) as usize;
    }
    if next.is_zero() {
        next = BigUint::one();
    }

    next = next.min(max);

    biguint_to_target(&next)
}

fn target_to_biguint(target: Target) -> BigUint {
    BigUint::from_bytes_be(&target.0)
}

fn biguint_to_target(value: &BigUint) -> Result<Target, DifficultyError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(DifficultyError::TargetOverflow);
    }

    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    Ok(Target(out))
}

#[derive(Debug, Error)]
pub enum DifficultyError {
    #[error("expected timespan must be > 0")]
    InvalidExpectedTimespan,
    #[error("invalid retarget clamp: {0}")]
    InvalidClamp(String),
    #[error("insufficient difficulty history: needed at least {needed}, got {got}")]
    InsufficientHistory { needed: usize, got: usize },
    #[error("invalid history layout for difficulty algorithm")]
    InvalidHistoryLayout,
    #[error("new target overflows 256 bits")]
    TargetOverflow,
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;
    use scam_core::Target;

    use crate::difficulty::{asert_next, chainwork_for_target, lwma_next, retarget_next};

    #[test]
    fn slower_blocks_increase_target() {
        let old =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target must parse");
        let next = retarget_next(old, 4000, 2400, 0.25, 4.0, Target::MAX).expect("retarget");
        assert!(next > old);
    }

    #[test]
    fn faster_blocks_decrease_target() {
        let old =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target must parse");
        let next = retarget_next(old, 1200, 2400, 0.25, 4.0, Target::MAX).expect("retarget");
        assert!(next < old);
    }

    #[test]
    fn clamp_applies() {
        let old =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target must parse");
        let next = retarget_next(old, 999_999, 2400, 0.25, 2.0, Target::MAX).expect("retarget");
        let max_expected = retarget_next(old, 4800, 2400, 0.25, 2.0, Target::MAX)
            .expect("retarget with clamped max");
        assert_eq!(next, max_expected);
    }

    #[test]
    fn chainwork_is_higher_for_lower_target() {
        let easier =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target must parse");
        let harder =
            Target::from_hex("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target must parse");
        assert!(chainwork_for_target(harder) > chainwork_for_target(easier));
    }

    #[test]
    fn lwma_reacts_to_faster_blocks() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let targets = vec![target; 5];
        let timestamps = vec![1000, 1020, 1040, 1060, 1080];
        let next = lwma_next(&targets, &timestamps, 120, Target::MAX).expect("lwma");
        assert!(next < target);
    }

    #[test]
    fn asert_reacts_to_slower_blocks() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let next = asert_next(target, 240, 120, 600, Target::MAX).expect("asert");
        assert!(next > target);
    }

    #[test]
    fn retarget_rejects_invalid_expected_timespan() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let err = retarget_next(target, 10, 0, 0.25, 4.0, Target::MAX).expect_err("must fail");
        assert!(matches!(
            err,
            crate::difficulty::DifficultyError::InvalidExpectedTimespan
        ));
    }

    #[test]
    fn retarget_rejects_invalid_clamps() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");

        let up_err = retarget_next(target, 10, 20, 0.25, 0.99, Target::MAX).expect_err("must fail");
        assert!(matches!(
            up_err,
            crate::difficulty::DifficultyError::InvalidClamp(_)
        ));

        let down_err = retarget_next(target, 10, 20, 0.0, 4.0, Target::MAX).expect_err("must fail");
        assert!(matches!(
            down_err,
            crate::difficulty::DifficultyError::InvalidClamp(_)
        ));
    }

    #[test]
    fn retarget_clamps_actual_timespan_to_minimum_bound() {
        let old =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let next = retarget_next(old, 0, 2400, 0.25, 4.0, Target::MAX).expect("retarget");
        let min_bound = retarget_next(old, 600, 2400, 0.25, 4.0, Target::MAX).expect("retarget");
        assert_eq!(next, min_bound);
    }

    #[test]
    fn lwma_rejects_invalid_inputs() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let err_time = lwma_next(&[target, target], &[1, 2], 0, Target::MAX).expect_err("fail");
        assert!(matches!(
            err_time,
            crate::difficulty::DifficultyError::InvalidExpectedTimespan
        ));

        let err_layout = lwma_next(&[target, target], &[1], 120, Target::MAX).expect_err("fail");
        assert!(matches!(
            err_layout,
            crate::difficulty::DifficultyError::InsufficientHistory { .. }
                | crate::difficulty::DifficultyError::InvalidHistoryLayout
        ));

        let err_insufficient = lwma_next(&[target], &[1], 120, Target::MAX).expect_err("fail");
        assert!(matches!(
            err_insufficient,
            crate::difficulty::DifficultyError::InsufficientHistory { .. }
        ));
    }

    #[test]
    fn lwma_caps_extreme_solve_time_and_respects_max_target() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let targets = vec![target; 4];
        let timestamps = vec![1_000, 2_000_000, 4_000_000, 8_000_000];
        let capped_max =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let next = lwma_next(&targets, &timestamps, 120, capped_max).expect("lwma");
        assert!(next <= capped_max);
    }

    #[test]
    fn asert_rejects_invalid_parameters() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let err_half = asert_next(target, 120, 120, 0, Target::MAX).expect_err("must fail");
        assert!(matches!(
            err_half,
            crate::difficulty::DifficultyError::InvalidClamp(_)
        ));

        let err_time = asert_next(target, 120, 0, 600, Target::MAX).expect_err("must fail");
        assert!(matches!(
            err_time,
            crate::difficulty::DifficultyError::InvalidExpectedTimespan
        ));
    }

    #[test]
    fn asert_large_negative_delta_never_underflows_to_zero() {
        let target =
            Target::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let next = asert_next(target, 1, 10_000, 1, Target::MAX).expect("asert");
        assert!(next > Target::MIN);
    }

    #[test]
    fn retarget_accepts_clamp_boundaries_equal_to_one() {
        let old =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let next = retarget_next(old, 2400, 2400, 1.0, 1.0, Target::MAX).expect("retarget");
        assert_eq!(next, old);
    }

    #[test]
    fn retarget_matches_reference_vectors() {
        let old =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let v1 = retarget_next(old, 4_000, 2_400, 0.25, 4.0, Target::MAX).expect("retarget v1");
        assert_eq!(
            v1,
            Target::from_hex("01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9")
                .expect("target parse")
        );

        let v2 = retarget_next(old, 0, 2_400, 0.25, 4.0, Target::MAX).expect("retarget v2");
        assert_eq!(
            v2,
            Target::from_hex("003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse")
        );

        let capped_max =
            Target::from_hex("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let v3 = retarget_next(old, 9_999_999, 2_400, 0.25, 2.0, capped_max)
            .expect("retarget clamp to max");
        assert_eq!(v3, capped_max);
    }

    #[test]
    fn lwma_rejects_layout_mismatch_when_lengths_differ_with_enough_history() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let err = lwma_next(&[target, target, target], &[1, 2], 120, Target::MAX)
            .expect_err("length mismatch must fail");
        assert!(matches!(
            err,
            crate::difficulty::DifficultyError::InvalidHistoryLayout
        ));
    }

    #[test]
    fn lwma_accepts_minimum_valid_history_of_two_entries() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let max = Target::MAX;
        let next = lwma_next(&[target, target], &[1_000, 1_120], 120, max).expect("lwma");
        assert_eq!(next, target);
    }

    #[test]
    fn lwma_reports_insufficient_history_when_only_one_side_is_short() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let err = lwma_next(&[target], &[1_000, 1_120], 120, Target::MAX).expect_err("must fail");
        assert!(matches!(
            err,
            crate::difficulty::DifficultyError::InsufficientHistory { needed: 2, got: 1 }
        ));
    }

    #[test]
    fn asert_keeps_target_when_observed_equals_expected() {
        let target =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let next = asert_next(target, 120, 120, 600, Target::MAX).expect("asert");
        assert_eq!(next, target);
    }

    #[test]
    fn asert_clamps_to_max_target() {
        let target =
            Target::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00")
                .expect("target parse");
        let next = asert_next(target, 10_000, 1, 1, Target::MAX).expect("asert");
        assert_eq!(next, Target::MAX);
    }

    #[test]
    fn chainwork_for_target_zero_is_zero() {
        assert_eq!(
            chainwork_for_target(Target::MIN),
            num_bigint::BigUint::from(0u8)
        );
    }

    #[test]
    fn chainwork_matches_reference_vectors() {
        let t1 =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let t2 =
            Target::from_hex("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let t3 =
            Target::from_hex("0000000000000000000000000000000000000000000000000000000000000010")
                .expect("target parse");
        assert_eq!(
            chainwork_for_target(t1),
            num_bigint::BigUint::from(0x100u64)
        );
        assert_eq!(
            chainwork_for_target(t2),
            num_bigint::BigUint::from(0x1_0000u64)
        );
        assert_eq!(
            chainwork_for_target(t3),
            num_bigint::BigUint::parse_bytes(
                b"f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
                16
            )
            .expect("hex parse")
        );
    }

    #[test]
    fn lwma_matches_reference_vectors() {
        let max = Target::MAX;
        let targets = vec![
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse"),
            Target::from_hex("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse"),
            Target::from_hex("003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse"),
            Target::from_hex("001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse"),
            Target::from_hex("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse"),
        ];

        let v1 = lwma_next(&targets, &[1_000, 1_120, 1_240, 1_360, 1_480], 120, max)
            .expect("lwma vector 1");
        assert_eq!(
            v1,
            Target::from_hex("003bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse")
        );

        let v2 =
            lwma_next(&targets, &[1_000, 1_010, 1_030, 1_060, 1_100], 120, max).expect("lwma v2");
        assert_eq!(
            v2,
            Target::from_hex("000effffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse")
        );

        let capped_max =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let v3 = lwma_next(
            &targets,
            &[1_000, 1_005, 1_008, 1_012, 1_016],
            120,
            capped_max,
        )
        .expect("lwma v3");
        assert_eq!(
            v3,
            Target::from_hex("0001f33333333333333333333333333333333333333333333333333333333333")
                .expect("target parse")
        );

        let v4 = lwma_next(&targets, &[1_000, 5_000, 9_000, 15_000, 21_000], 120, max)
            .expect("lwma vector 4");
        assert_eq!(
            v4,
            Target::from_hex("0167fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa")
                .expect("target parse")
        );
    }

    /// Alternating future/past timestamps must not lower difficulty. With
    /// raw pairwise deltas each `(+5T, back)` pair recorded `6T + 1`
    /// seconds for `2T` of real time.
    #[test]
    fn lwma_resists_alternating_timestamp_manipulation() {
        let t = 120u64;
        let window = 30usize;
        let target =
            Target::from_hex("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let targets = vec![target; window + 1];
        let honest: Vec<u64> = (0..=window as u64).map(|i| 10_000 + i * t).collect();
        let manipulated: Vec<u64> = honest
            .iter()
            .enumerate()
            .map(|(i, ts)| if i % 2 == 1 { ts + 5 * t } else { *ts })
            .collect();

        let honest_next = lwma_next(&targets, &honest, t, Target::MAX).expect("honest");
        let manipulated_next =
            lwma_next(&targets, &manipulated, t, Target::MAX).expect("manipulated");
        let honest_big = BigUint::from_bytes_be(&honest_next.0);
        let manipulated_big = BigUint::from_bytes_be(&manipulated_next.0);
        // Allow a small one-off gain from the first forward stamp, but not
        // the ~3x ratchet the old code produced.
        assert!(
            manipulated_big * BigUint::from(4u32) <= honest_big * BigUint::from(5u32),
            "manipulated target {manipulated_next} must stay within 25% of honest {honest_next}"
        );
    }

    /// The integer approximation must track the exact `2^x` closely across
    /// the whole fractional range (test-only use of `powf` as a reference).
    #[test]
    fn asert_integer_factor_tracks_exact_exponential() {
        let base =
            Target::from_hex("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let base_f = BigUint::from_bytes_be(&base.0).to_f64().expect("f64");
        for observed in (0u64..=7_200).step_by(37) {
            let next = asert_next(base, observed, 120, 3_600, Target::MAX).expect("asert");
            let got = BigUint::from_bytes_be(&next.0).to_f64().expect("f64");
            let exact = base_f * 2f64.powf((observed as f64 - 120.0) / 3_600.0);
            let rel = ((got - exact) / exact).abs();
            assert!(rel < 2e-4, "observed={observed} rel_err={rel}");
        }
    }

    #[test]
    fn asert_huge_solvetime_saturates_without_huge_allocation() {
        let base =
            Target::from_hex("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let next = asert_next(base, u64::MAX, 120, 1, Target::MAX).expect("asert");
        assert_eq!(next, Target::MAX);
    }

    /// Vectors for the integer (aserti3-2d style) evaluation. They must be
    /// bit-identical on every platform; regenerate only with a deliberate
    /// consensus change.
    #[test]
    fn asert_matches_reference_vectors() {
        let max = Target::MAX;
        let base =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");

        let v1 = asert_next(base, 120, 120, 3_600, max).expect("asert v1");
        assert_eq!(
            v1,
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse")
        );

        let v2 = asert_next(base, 240, 120, 3_600, max).expect("asert v2");
        assert_eq!(
            v2,
            Target::from_hex("0105fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")
                .expect("target parse")
        );

        let v3 = asert_next(base, 60, 120, 3_600, max).expect("asert v3");
        assert_eq!(
            v3,
            Target::from_hex("00fd107fffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse")
        );

        let harder =
            Target::from_hex("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let v4 = asert_next(harder, 7_200, 120, 600, max).expect("asert v4");
        assert_eq!(
            v4,
            Target::from_hex("0dee17fffffffffffffffffffffffffffffffffffffffffffffffffffffff211")
                .expect("target parse")
        );

        let v5 = asert_next(base, 1, 100_000, 1, max).expect("asert v5");
        assert_eq!(
            v5,
            Target::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .expect("target parse")
        );
    }
}
