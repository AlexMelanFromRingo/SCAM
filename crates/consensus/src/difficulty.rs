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
    if next > max {
        next = max;
    }

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

    for i in 1..=n {
        let solve_time = recent_timestamps[i]
            .saturating_sub(recent_timestamps[i - 1])
            .clamp(1, max_solve_time);
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
    if next > max {
        next = max;
    }

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

    let delta = (observed_solvetime_sec as i128) - (target_block_time_sec as i128);
    let exponent = (delta as f64) / (half_life_sec as f64);
    let int_part = exponent.floor() as i64;
    let frac_part = exponent - (int_part as f64);
    let frac_multiplier = 2f64.powf(frac_part);
    let frac_scale = 1_000_000_000u64;
    let frac_scaled = (frac_multiplier * frac_scale as f64).round().max(1.0) as u64;

    let mut base = target_to_biguint(previous_target);
    if int_part >= 0 {
        base <<= int_part as usize;
    } else {
        let shift = (-int_part) as usize;
        if shift >= 256 {
            base = BigUint::one();
        } else {
            base >>= shift;
            if base.is_zero() {
                base = BigUint::one();
            }
        }
    }

    let mut next = (base * BigUint::from(frac_scaled)) / BigUint::from(frac_scale);
    if next.is_zero() {
        next = BigUint::one();
    }

    let max = target_to_biguint(max_target);
    if next > max {
        next = max;
    }

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
            Target::from_hex("0105fbd4d5b861637ad73f4a206832f7d79b0f9902ce6f16ecb4266b57449309")
                .expect("target parse")
        );

        let v3 = asert_next(base, 60, 120, 3_600, max).expect("asert v3");
        assert_eq!(
            v3,
            Target::from_hex("00fd0f413daf5a6d812f36f1a61778b9f276f7d07dfeaae2b99584d96583dfbe")
                .expect("target parse")
        );

        let harder =
            Target::from_hex("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target parse");
        let v4 = asert_next(harder, 7_200, 120, 600, max).expect("asert v4");
        assert_eq!(
            v4,
            Target::from_hex("0dedc66d7bf32f50ea42176b70554169c686fc4cdbea90c6d0f91b2335d3d847")
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
