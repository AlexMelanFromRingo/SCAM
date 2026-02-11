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
    #[error("new target overflows 256 bits")]
    TargetOverflow,
}

#[cfg(test)]
mod tests {
    use scam_core::Target;

    use crate::difficulty::{chainwork_for_target, retarget_next};

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
}
