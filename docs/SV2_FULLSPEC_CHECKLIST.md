# SV2 Full-Spec Checklist (SCAM Profile)

Status date: 2026-02-26

Scope note:
- This checklist tracks full coverage for the SV2 surface implemented by SCAM
  (pool-side serve + conformance tooling profile).
- It is not a claim that all possible third-party vendor extensions are already
  interoperable by default.

## 1) Setup and Transport

- [x] `SetupConnection` success path.
- [x] `SetupConnectionError` path.
- [x] Setup protocol/version negotiation guards.
- [x] Setup feature-flags allow/deny guards.
- [x] Legacy secure transport mode.
- [x] Noise XX secure transport mode.
- [x] Noise replay ciphertext rejection test coverage.
- [x] Frame length/type/malformed input bounds checks (sync + async paths).

## 2) Channel Lifecycle

- [x] `OpenStandardMiningChannel` success path.
- [x] `OpenStandardMiningChannelError` path.
- [x] Out-of-order open/submit state rejection.
- [x] Extended-channel open request rejection with explicit
      `OpenExtendedMiningChannelError` response (`unsupported_channel_type`).

## 3) Job and Target Flow

- [x] `NewMiningJob` emission and validation path.
- [x] `SetNewPrevHash` path with channel validation.
- [x] `SetTarget` updates and conformance assertions.
- [x] `Reconnect` message handling path.

## 4) Share Submission

- [x] `SubmitSharesStandard` accept path.
- [x] `SubmitSharesSuccess` response path.
- [x] `SubmitSharesError` response path.
- [x] Unknown/out-of-state submit rejection.
- [x] Extended share submit rejection with explicit
      `SubmitSharesError` response (`unsupported_submit_type`).

## 5) Negative Path Hardening

- [x] Explicit protocol violation mapping to deterministic SV2 error responses
      where wire-compatible.
- [x] Per-session protocol violation budget with forced close on threshold.
- [x] Handshake timeout enforcement.
- [x] Inbound per-IP accept-rate limiting for Stratum listener.

## 6) Conformance Tooling

- [x] Required observed kinds gate.
- [x] Forbidden observed kinds gate.
- [x] Required observed sequence gate (ordered).
- [x] Setup version/flag mask strict gates.
- [x] Per-target timeout/retry knobs for external matrix rows.
- [x] Expected `pass/fail` gating and artifacted matrix status.

## 7) External Matrix and Release Gate

- [x] Structured external target manifest schema.
- [x] Vendor/version/workaround metadata in result artifacts.
- [x] Golden corpus freeze + verify tooling.
- [x] Release gate script/workflow with optional strict external requirement.

## 8) Remaining Non-Code Gates

- [ ] Mutation rerun/closure on latest commit set (`stage2/stage3`).
- [ ] Long-run soak and chaos acceptance.
- [ ] External security audit for production blocking findings.
