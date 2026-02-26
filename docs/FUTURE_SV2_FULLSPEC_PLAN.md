# Future Plan: Full-Spec SV2 + External Interop

Status: post-MVP roadmap.  
Scope: future work only.  
Note: this file does not change or replace current completed TODO files.
Clarification: consensus is already functionally implemented; future items touching consensus are hardening/audit/test-depth tasks, not a redesign.

## 0) Immediate Execution Order (Requested)

- [x] Wait for the running mutation baseline to finish and freeze report artifacts.
  - Latest staged baseline artifact frozen at:
    `target/mutants-stage/stage1/mutants.out/outcomes.json` (`end_time=2026-02-13T21:05:37Z`).
- [x] Create a private GitHub repository and push the project with full commit history (no squashing).
  - Remote: `https://github.com/AlexMelanFromRingo/SCAM` (private).
- [x] Verify remote integrity (`git log`, tags/branches if present, and repository visibility).
  - Verified branch mapping and visibility via GitHub CLI (`gh repo view`).
- [ ] Continue post-publish hardening work:
- [ ] mutation-gap closure in `core/consensus/node`,
- [x] expanded external SV2 interoperability matrix automation (`SV2_EXTERNAL_TARGETS_FILE` extended schema, per-target timeout/retry/gating knobs, quirks/workaround metadata artifacts),
- [x] final launch hardening and operator runbook/release-gate polish (`scripts/sv2-release-gate.sh`, workflow `sv2-release-gate.yml`, runbook section updates).

## 1) Target Outcome

- Deliver full-spec Stratum V2 behavior (not only subset flows).
- Prove interoperability with external SV2 stacks in repeatable CI runs.
- Reach pool-grade readiness for mixed-vendor miners and operators.

## 2) Workstreams

### A. Protocol Completeness

- [~] Build a strict spec map: each required message, state transition, and error path.
  - Conformance harness now supports strict observed-kind gates (`--require-observed-kind`, `--forbid-observed-kind`)
    and submit-share context autofill from discovered channel/job state.
- [~] Implement all required channel types and lifecycle paths.
  - Added corpus path `docs/sv2-corpus/full-spec-submit.json` to assert submit/share state-path behavior.
- [ ] Add complete capability negotiation and version/feature compatibility handling.
- [~] Add full negative-path handling for malformed/unsupported/out-of-order messages.
  - External matrix now supports expected-fail rows with vendor-specific workaround/notes tracking.
  - Added setup version/flags strict gates and observed-kind allow/deny enforcement in conformance runner.

### B. Transport and Security

- Keep `noise_xx` as default secure mode and harden all edge cases.
- Add replay/ordering abuse tests for encrypted channels.
- Expand key lifecycle policy: rotation playbooks, rollback, and emergency revoke.
- Add stricter limits for handshake floods and malformed frame storms.

### C. External Interoperability

- [x] Define external target matrix (vendor, version, mode, role, expected behavior).
- [x] Run automated compatibility scenarios against each target stack.
- [x] Maintain golden corpus of cross-stack captures and expected outcomes.
  - Added `scripts/sv2-golden-freeze.sh`, `scripts/sv2-golden-verify.py`, and baseline
    `docs/sv2-corpus/golden/expectations.json` wired into release gate (`VERIFY_GOLDEN=true`).
- [x] Track compatibility quirks by stack/version with explicit workarounds.
- Baseline harness support is in place for structured target manifests (`SV2_EXTERNAL_TARGETS_FILE`)
  with per-target expected outcome + vendor/version metadata artifacts.
- Added dedicated manual CI workflow for external stacks (`.github/workflows/sv2-external-interop.yml`)
  driven by secret manifest `SV2_EXTERNAL_TARGETS_JSON`.
- Added dedicated release gate workflow (`.github/workflows/sv2-release-gate.yml`) with strict external-rows option.

### D. Scale and Reliability

- Stress test high-connection scenarios (1k, 5k, 10k workers).
- Add long-run soak for SV2 role split with fault injection.
- Add performance budgets and regressions gates in CI.

### E. Validation and Quality

- Expand mutation targets in `core/consensus/node` where missed mutants are highest (consensus hardening only).
- Add property tests for protocol invariants and message ordering invariants.
- Add deterministic replay harness for protocol transcripts.

### F. External Security Review

- Commission external audit for:
- consensus-critical paths,
- wallet/signing/vault paths,
- p2p/stratum transport and abuse resistance.
- Run bug bounty after audit fixes are merged.

## 3) Delivery Phases

### Phase 1: Spec Coverage Baseline (2-4 weeks)

- Freeze protocol checklist.
- Implement missing required message/state paths.
- Add protocol conformance unit/integration tests.

Exit criteria:
- Spec checklist shows no uncovered required paths.
- Conformance suite passes locally and in CI.

### Phase 2: Interop Matrix (3-6 weeks)

- Integrate external stacks into automated matrix runs.
- Resolve incompatibilities and document vendor quirks.

Exit criteria:
- Stable pass-rate across supported external stacks.
- Published compatibility matrix with versions and known limits.

### Phase 3: Pool-Grade Hardening (3-6 weeks)

- High-load/stability/perf runs.
- External audit + remediation.
- Public testnet dress rehearsal with mixed clients.

Exit criteria:
- Soak/perf targets met.
- Audit critical/high findings resolved.
- Public rehearsal success without sev-1 incidents.

## 4) Release Gate (Go / No-Go)

- [ ] Full-spec checklist complete.
- [x] Interop matrix green for supported targets (local + external expected-result gate in `scripts/sv2-release-gate.sh`).
- [ ] Security audit closed for blocking findings.
- [ ] Long-run soak and chaos criteria met.
- [x] Operator runbook updated for final conformance/release-gate flows.
