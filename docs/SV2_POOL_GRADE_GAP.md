# SV2 Pool-Grade Gap Plan

Current status: all tracked gap items in this file are implemented in-repo.

## 1) Role Split

- [x] Introduce explicit Template Provider role (local runtime provider baseline).
- [x] Introduce explicit Job Declarator role (monotonic sequential declarator).
- [x] Introduce explicit Translator role (remote job message translator).
- [x] Externalize roles into independent pool services with network boundaries.
  - Commands: `sv2-template-provider`, `sv2-job-declarator`, `sv2-translator`.
- [x] Define role interfaces and failure domains.
  - See: `docs/SV2_ROLE_INTERFACES.md`.

## 2) Transport Security

- [x] Add encrypted transport baseline (ECDH handshake + AEAD frame protection).
- [x] Integrate full Noise-spec encrypted channels.
  - Mode: `noise_xx` (`--secure-transport-mode noise-xx`).
- [x] Add baseline key rotation policy (message-count rekey interval in config/CLI).
- [x] Add production key lifecycle and rotation policy (identity management + rotation operations).
  - Commands: `stratum-keygen`, `stratum-key-rotate`.
- [x] Add secure handshake/error handling tests.
  - Coverage in `crates/stratum/src/lib.rs` tests for legacy + noise transport paths.

## 3) Interoperability Matrix

- [x] Build compatibility matrix with third-party SV2 stacks.
  - Harness: `scripts/sv2-conformance-matrix.sh`.
- [x] Add message corpus replay against external implementations.
  - Command: `sv2-conformance --corpus <file>`, script: `scripts/sv2-corpus-replay.sh`.
- [x] Add conformance report in CI artifacts.
  - Workflow: `.github/workflows/ci.yml` uploads `target/sv2-conformance`.

## 4) Operational Readiness

- [x] Add role-specific telemetry dashboards.
  - Telemetry snapshots: role service `--telemetry-out`.
  - Dashboard tool: `scripts/role-telemetry-dashboard.py`.
- [x] Add staged rollout policy for protocol changes.
  - See: `docs/SV2_ROLLOUT_POLICY.md`.
- [x] Publish incident runbook for pool-role failures.
  - See: `docs/SV2_ROLE_INCIDENT_RUNBOOK.md`.

