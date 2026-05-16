//! BIP9-style soft-fork deployment state machine.
//!
//! See `docs/PROTOCOL_DESIGN.md` §2. Bitcoin's BIP9 in one paragraph:
//! every deployment carries a bit slot in the block header `version`
//! field. Once `start_unix` MTP has passed, the chain enters STARTED.
//! Every retarget window (BIP9 uses 2016 blocks; SCAM parameterizes it)
//! we tally how many headers in the prior window had the deployment bit
//! set. If ≥ threshold, we go to LOCKED_IN, then automatically to ACTIVE
//! one window later. If timeout MTP is reached first, FAILED. Both
//! ACTIVE and FAILED are terminal.
//!
//! This module is pure (no I/O, no chain runtime) so the state-machine
//! logic can be exhaustively tested with synthetic inputs.

use serde::{Deserialize, Serialize};

/// Header version bits 31..29 must equal `0b001` for the deployment-bit
/// signaling rule to apply. Anything else falls back to "no signal".
/// Matches BIP9 verbatim.
pub const VERSIONBITS_TOP_MASK: u32 = 0xE000_0000;
pub const VERSIONBITS_TOP_BITS: u32 = 0x2000_0000;

/// Maximum deployment bit index. BIP9 reserves bits 29/30/31 (top mask)
/// for the magic prefix, so deployments live in 0..=28.
pub const VERSIONBITS_MAX_BIT: u8 = 28;

/// Returns true iff `version` signals the deployment at `bit`, *and*
/// the magic-prefix rule holds. Never panics; out-of-range bit returns
/// false rather than wrapping.
pub fn deployment_bit_signaled(version: u32, bit: u8) -> bool {
    if bit > VERSIONBITS_MAX_BIT {
        return false;
    }
    if version & VERSIONBITS_TOP_MASK != VERSIONBITS_TOP_BITS {
        return false;
    }
    (version >> bit) & 1 == 1
}

/// A single soft-fork deployment. Identified by name (for logging /
/// telemetry) and bit (for signaling).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Deployment {
    pub name: String,
    pub bit: u8,
    /// MTP at which signaling may begin. Until reached, state is DEFINED.
    pub start_unix: u64,
    /// MTP at which signaling fails if not yet locked in.
    pub timeout_unix: u64,
}

impl Deployment {
    pub fn is_valid_bit(&self) -> bool {
        self.bit <= VERSIONBITS_MAX_BIT
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeploymentState {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

/// Inputs to the per-window state-transition function.
///
/// `bit_count_in_prior_window` is the number of headers in the previous
/// retarget window whose `version` signaled this deployment. `window_mtp`
/// is the MTP at the boundary of the new window. `threshold` and
/// `window_blocks` come from chain config.
///
/// Returns the new state after the transition. Behaviorally identical
/// to Bitcoin Core's `AbstractThresholdConditionChecker::GetStateFor`
/// but reduced to a pure function for testing.
pub fn next_state(
    previous: DeploymentState,
    bit_count_in_prior_window: u32,
    window_mtp: u64,
    deployment: &Deployment,
    threshold: u32,
    _window_blocks: u64,
) -> DeploymentState {
    match previous {
        DeploymentState::Defined => {
            if window_mtp >= deployment.timeout_unix {
                DeploymentState::Failed
            } else if window_mtp >= deployment.start_unix {
                DeploymentState::Started
            } else {
                DeploymentState::Defined
            }
        }
        DeploymentState::Started => {
            if window_mtp >= deployment.timeout_unix {
                DeploymentState::Failed
            } else if bit_count_in_prior_window >= threshold {
                DeploymentState::LockedIn
            } else {
                DeploymentState::Started
            }
        }
        DeploymentState::LockedIn => DeploymentState::Active,
        DeploymentState::Active => DeploymentState::Active,
        DeploymentState::Failed => DeploymentState::Failed,
    }
}

/// Walk the state machine from DEFINED across a series of `(count, mtp)`
/// observations, one per retarget window. Convenience for tests + ops
/// dashboards; production callers should evaluate one transition at a
/// time and cache the result per-window-boundary.
pub fn evaluate_from_history(
    deployment: &Deployment,
    threshold: u32,
    window_blocks: u64,
    history: &[(u32, u64)],
) -> DeploymentState {
    let mut state = DeploymentState::Defined;
    for &(count, mtp) in history {
        state = next_state(state, count, mtp, deployment, threshold, window_blocks);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(bit: u8, start: u64, timeout: u64) -> Deployment {
        Deployment {
            name: "test".to_owned(),
            bit,
            start_unix: start,
            timeout_unix: timeout,
        }
    }

    #[test]
    fn bit_signal_requires_magic_prefix_and_bit_set() {
        // Bit 0 set, magic prefix correct.
        assert!(deployment_bit_signaled(0x2000_0001, 0));
        // Bit 1 set, magic prefix correct.
        assert!(deployment_bit_signaled(0x2000_0002, 1));
        // Bit 0 set but magic prefix wrong → no signal.
        assert!(!deployment_bit_signaled(0x0000_0001, 0));
        assert!(!deployment_bit_signaled(0x4000_0001, 0));
        // Bit 0 NOT set despite magic prefix.
        assert!(!deployment_bit_signaled(0x2000_0002, 0));
        // Bit index out of range.
        assert!(!deployment_bit_signaled(0xFFFF_FFFF, 29));
        assert!(!deployment_bit_signaled(0xFFFF_FFFF, 200));
    }

    #[test]
    fn defined_to_started_when_mtp_crosses_start() {
        let d = dep(0, 100, 1_000);
        // Below start: stay defined.
        assert_eq!(
            next_state(DeploymentState::Defined, 0, 50, &d, 10, 100),
            DeploymentState::Defined
        );
        // At start: go started.
        assert_eq!(
            next_state(DeploymentState::Defined, 0, 100, &d, 10, 100),
            DeploymentState::Started
        );
    }

    #[test]
    fn defined_can_jump_straight_to_failed_if_window_skips_past_timeout() {
        let d = dep(0, 100, 1_000);
        // Skipped over the entire window — start IS past, timeout ALSO
        // past. Bitcoin rule: failed takes precedence.
        assert_eq!(
            next_state(DeploymentState::Defined, 0, 2_000, &d, 10, 100),
            DeploymentState::Failed
        );
    }

    #[test]
    fn started_locks_in_at_threshold_else_continues() {
        let d = dep(0, 100, 1_000);
        // Below threshold: stay started.
        assert_eq!(
            next_state(DeploymentState::Started, 5, 200, &d, 10, 100),
            DeploymentState::Started
        );
        // Hit threshold exactly: lock in.
        assert_eq!(
            next_state(DeploymentState::Started, 10, 200, &d, 10, 100),
            DeploymentState::LockedIn
        );
        // Above threshold: also locks in.
        assert_eq!(
            next_state(DeploymentState::Started, 95, 200, &d, 10, 100),
            DeploymentState::LockedIn
        );
    }

    #[test]
    fn started_fails_at_timeout_even_if_threshold_would_have_been_met() {
        let d = dep(0, 100, 1_000);
        // Bitcoin's rule: timeout check precedes threshold check.
        assert_eq!(
            next_state(DeploymentState::Started, 9999, 1_000, &d, 10, 100),
            DeploymentState::Failed
        );
    }

    #[test]
    fn locked_in_then_active_is_automatic_terminal() {
        let d = dep(0, 100, 1_000);
        assert_eq!(
            next_state(DeploymentState::LockedIn, 0, 5_000_000, &d, 10, 100),
            DeploymentState::Active
        );
        // Active stays active even after timeout.
        assert_eq!(
            next_state(DeploymentState::Active, 0, 5_000_000, &d, 10, 100),
            DeploymentState::Active
        );
        assert_eq!(
            next_state(DeploymentState::Failed, 9999, 5_000_000, &d, 10, 100),
            DeploymentState::Failed
        );
    }

    #[test]
    fn end_to_end_lockin_path() {
        let d = dep(3, 200, 2_000);
        // history of (bit_count, mtp) per window
        let history = [
            (0, 100),   // before start → DEFINED
            (0, 250),   // started
            (50, 400),  // still started (5 < threshold 10)
            (10, 600),  // locked in (10 >= 10)
            (0, 800),   // active
            (0, 5_000), // active stays terminal
        ];
        assert_eq!(
            evaluate_from_history(&d, 10, 100, &history),
            DeploymentState::Active
        );
    }

    #[test]
    fn end_to_end_failure_path() {
        let d = dep(3, 200, 1_000);
        let history = [
            (0, 100),    // defined
            (0, 250),    // started
            (5, 500),    // still started
            (5, 999),    // still started (just under timeout)
            (5, 1_000),  // failed at timeout
            (50, 1_500), // stays failed
        ];
        assert_eq!(
            evaluate_from_history(&d, 10, 100, &history),
            DeploymentState::Failed
        );
    }

    #[test]
    fn deployment_bit_validation_catches_oob() {
        assert!(dep(0, 0, 0).is_valid_bit());
        assert!(dep(28, 0, 0).is_valid_bit());
        assert!(!dep(29, 0, 0).is_valid_bit());
        assert!(!dep(255, 0, 0).is_valid_bit());
    }
}
