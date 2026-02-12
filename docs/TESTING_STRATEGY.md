# Testing Strategy Baseline

## Unit / Integration / Property Tests

Primary baseline is run with:

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

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
  --sleep-per-round-sec 120
```

This runs for ~24h wall-clock time (720 rounds with 120-second sleeps) at 2-minute block cadence and includes transaction churn.

Shortcut script:

```bash
scripts/soak-24h.sh
```
