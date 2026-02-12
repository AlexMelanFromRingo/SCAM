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
  --rounds 17280 \
  --blocks-per-round 1 \
  --interval-sec 120 \
  --persist-every-rounds 60
```

This approximates a 24h run at 2-minute block cadence.
