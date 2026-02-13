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
}
