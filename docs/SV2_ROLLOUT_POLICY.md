# SV2 Staged Rollout Policy

This policy is used for protocol and transport changes in SCAM Stratum/SV2 paths.

## 1) Stages

1. `lab`
- local-only rollout (`devnet`), matrix checks must pass on local plaintext + secure modes.

2. `canary`
- limited operators/miners, secure mode enabled for a subset of pool endpoints.
- rollback trigger: conformance failure, handshake error spike, reject-rate regression.

3. `broad`
- production testnet rollout with full operator set.
- requirement: stable telemetry trend and no unresolved incident from canary.

4. `default`
- new version becomes default in config templates and operator runbooks.

## 2) Promotion Gates

- `cargo test --workspace` green.
- `cargo clippy --workspace --all-targets -- -D warnings` green.
- `scripts/sv2-conformance-matrix.sh` pass.
- role-service telemetry error-rate within threshold.
- no open Sev-1/Sev-2 incidents linked to the new protocol version.

## 3) Rollback Rules

- Keep previous binary and previous config bundle available.
- Roll back immediately if any of:
  - handshake failure surge,
  - share-acceptance collapse,
  - role service hard outage.
- After rollback:
  - freeze new rollout,
  - publish incident timeline,
  - create corrective patch + new canary cycle.

