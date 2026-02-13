# Forking Guide (Config-First)

SCAM is now designed for config-first network creation.

## 1) Generate a New Network Config

Use the built-in constructor command:

```bash
cargo run -p scam-node -- config-scaffold \
  --network-id myfork \
  --hrp sc \
  --target-block-time-sec 120 \
  --difficulty-algorithm lwma \
  --difficulty-adjustment-window 20 \
  --asert-half-life-sec 3600 \
  --dns-seed seed1.myfork.org \
  --dns-seed seed2.myfork.org \
  --out config/myfork.toml
```

## 2) Boot the New Chain

```bash
cargo run -p scam-node -- node run --network devnet --config config/myfork.toml --runtime-db data/myfork.runtime.redb
```

## 3) Start SV2 Mining Endpoint

```bash
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/myfork.toml \
  --runtime-db data/myfork.runtime.redb \
  --bind 0.0.0.0:3347 \
  --vardiff-target-shares-per-minute 6 \
  --vardiff-retarget-interval-shares 24 \
  --max-rejected-shares 64 \
  --max-jobs-per-channel 128
```

## What Is Safe To Change In Config

- `hrp`: yes (`s` -> `sc` etc.; must start with `s`).
- `genesis_*`: yes, for distinct networks.
- `difficulty_algorithm`: yes (`windowed`, `lwma`, `asert`).
- `target_block_time_sec`, `difficulty_adjustment_window`, clamps: yes.
- P2P policy fields (`dns_seeds`, bucket cap): yes.
- Stratum policy fields (`share_target`, `min/max share target`, VarDiff knobs, client limits): yes.

## Quality Notes

A config constructor does **not** reduce quality if:

- validation remains strict (`ChainConfig::validate`),
- consensus-critical settings are explicit and versioned,
- presets are tested (`cargo test`, `cargo clippy`),
- network IDs and genesis are unique per deployment.

This project follows that model.
