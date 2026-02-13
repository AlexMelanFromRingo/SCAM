# Testing Strategy Baseline

## Unit / Integration / Property Tests

Primary baseline is run with:

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Stratum coverage is included in workspace tests (`scam-stratum`):

- frame encode/decode roundtrip,
- session state-machine happy path,
- unknown job rejection,
- reject-budget closure behavior,
- VarDiff target retune behavior.
- secure transport encrypted frame roundtrip and handshake magic rejection.
- secure transport rekey-interval rotation behavior.
- noise_xx secure transport handshake + rekey behavior.
- role-split primitives (`SequentialJobDeclarator`, `IdentityTranslator`) unit coverage.

Networking/mempool hardening coverage includes:

- per-peer replacement rate limit tests in `scam-p2p`,
- telemetry counters for replacement and orphan churn in `scam-mempool`,
- gossip telemetry counters for replacement-driven relay paths.

## Fuzzing Baseline

Fuzz harness package lives in `fuzz/` with targets:

- `wire_decode`
- `block_decode`
- `tx_decode`

Run examples:

```bash
cargo fuzz run wire_decode --manifest-path fuzz/Cargo.toml
cargo fuzz run block_decode --manifest-path fuzz/Cargo.toml
cargo fuzz run tx_decode --manifest-path fuzz/Cargo.toml
```

## Mutation Testing Baseline

Helper script:

```bash
scripts/mutation-baseline.sh
```

This invokes `cargo-mutants` for the workspace and writes report artifacts into `target/mutants`.

## Soak Harness

Long-run devnet soak command:

```bash
cargo run -p scam-node -- soak \
  --network devnet \
  --rounds 720 \
  --blocks-per-round 1 \
  --interval-sec 120 \
  --persist-every-rounds 60 \
  --txs-per-round 1 \
  --tx-amount 1000 \
  --tx-fee 1 \
  --telemetry-out data/soak.telemetry.jsonl \
  --telemetry-every-rounds 1 \
  --sleep-per-round-sec 120
```

This runs for ~24h wall-clock time (720 rounds with 120-second sleeps) at 2-minute block cadence and includes transaction churn.
Telemetry JSONL can be post-processed for alert thresholds on replacement/orphan churn.

Threshold checker:

```bash
scripts/telemetry-alert-check.py \
  --input data/soak.telemetry.jsonl \
  --max-rate-limited 0 \
  --max-orphan-pool-len 500 \
  --max-mempool-len 50000
```

Shortcut script:

```bash
scripts/soak-24h.sh
```

## Chaos Crash-Loop

Power-loss style durability run:

```bash
scripts/chaos-crash-loop.sh
```

This repeatedly kills the node process and validates DB reopen/recovery.

## Public Testnet Dress Rehearsal

```bash
scripts/testnet-dress-rehearsal.sh
```

This runs bootstrap/sync/short-soak/reindex/status checks in sequence.

## SV2 Conformance Matrix

Generate local + external stack conformance reports:

```bash
scripts/sv2-conformance-matrix.sh
```

Replay corpus against one endpoint:

```bash
POOL=127.0.0.1:3347 scripts/sv2-corpus-replay.sh
```

Aggregate report artifacts:

```bash
python3 scripts/sv2-conformance-report.py \
  --input-dir target/sv2-conformance \
  --summary-out target/sv2-conformance/summary.json \
  --matrix-out target/sv2-conformance/matrix.md
```
