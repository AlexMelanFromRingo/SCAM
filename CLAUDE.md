# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SCAM ("Smart Computing Alternative Money") is a Rust 2024 implementation of a PoW L1 blockchain (BLAKE3-256 PoW, Schnorr/secp256k1 signatures, Bech32m addresses, UTXO model, SV2 stratum subset). The workspace is currently at `0.3.0` (`Cargo.toml`); the operator-facing README is the canonical end-user reference.

## Quality gates (must all pass before considering work done)

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

`-D warnings` is enforced — fix new clippy lints, do not `allow` them. Every crate root also pins `#![cfg_attr(not(test), deny(clippy::unwrap_used))]`; in non-test code use `?`, `expect("invariant: …")`, or explicit error paths instead of `unwrap()`.

## Tests

- `scam-node`'s bin tests run **single-threaded** (CI does this explicitly because the binary spins up sockets/ports/files):
  ```bash
  cargo test --workspace --exclude scam-node
  cargo test -p scam-node --bin scam-node -- --test-threads=1
  ```
- Run a single test: `cargo test -p <crate> <test_name>` (add `-- --test-threads=1` if it touches the node binary).
- Integration tests live under `crates/<name>/tests/`. The largest test surface (~310 cases) is `crates/node/src/main.rs` inline `#[cfg(test)]`.

## Mutation testing (`cargo-mutants`)

Use the staged runner — full workspace mutation is hours-long and flaky:

```bash
scripts/mutation-staged.sh stage1   # core/consensus/chain/mempool/miner
scripts/mutation-staged.sh stage2   # stratum/p2p/node
scripts/mutation-staged.sh stage3   # full workspace
```

Scope to specific packages when iterating: `MUTATION_PACKAGES="scam-core scam-consensus" scripts/mutation-baseline.sh`. RC gates require `0 missed` / `0 timeout` on stage2 closure + full stage3.

## Fuzzing (nightly only)

```bash
cargo +nightly fuzz run wire_decode    --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz run block_decode   --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz run tx_decode      --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz run relay_tx_submit --manifest-path fuzz/Cargo.toml
```

## Architecture (the big picture)

The workspace is layered — each crate depends only on crates below it. The integration layer is `scam-node`.

| Layer | Crates | Responsibility |
|---|---|---|
| Protocol primitives | `core` | Canonical bytes, BLAKE3 hashes, `Target`, `Block`/`Transaction` types, `ChainConfig`/genesis construction. |
| Validation | `consensus` | Block/tx validation, UTXO set, difficulty math (`windowed` / `lwma` / `asert`). |
| Active-tip selection | `chain` | `ChainRuntime`: cumulative-work fork choice, reorg via disconnect/connect of `BlockUndo`. |
| Mempool | `mempool` | Fee-aware replacement, descendant guardrails, orphan pool with TTL, telemetry. |
| Mining | `miner` | CPFP-aware template assembly, nonce loops (`mine_block_with_extra_nonce`). |
| Networking | `p2p` | Wire codec, sync, gossip (3137-line `gossip.rs`), transport with both blocking and async (`tokio`) APIs, peer discovery + replacement rate-limits. |
| SV2/Stratum | `stratum` | Binary framing, typed session state machine, role-split primitives (`SequentialJobDeclarator`, `IdentityTranslator`), legacy + `noise_xx` secure transports. |
| Wallet | `wallet` | BIP39 mnemonic, HD derivation, Schnorr signing, Argon2id+XChaCha20Poly1305 vault, rescan, QR/payment URI. |
| Persistence | `storage` | `redb`-backed archive, peer book, mempool snapshot, pool ledger. |
| RPC types | `rpc` | Shared request/response types for the HTTP API. |
| Integration | `node` | All CLI subcommands, runtime services, RPC routes, Axum web console wiring. |

### `crates/node/src/main.rs` is intentionally one ~41k-line file

All process roles (`node`, `relay-serve`, `rpc-serve`, `stratum-serve`, `stratum-mine`, `sv2-template-provider`, `sv2-job-declarator`, `sv2-translator`, `sv2-conformance`, soak/chaos harnesses, snapshot/reindex tools, every `wallet …` subcommand) are wired here. The `Command` enum at line 106 is the entry point for navigation. Inline `#[cfg(test)]` blocks contain the largest test surface in the repo — when adding behavior, add a unit test in the same file next to the helper rather than creating a new module.

### Process roles at runtime

- `node` — bootstraps runtime DB from config/genesis and exits.
- `relay-serve` — long-running P2P loop (handshake, INV/GETDATA, gossip, per-peer replacement-rate controls).
- `rpc-serve` — Axum HTTP + SSE + static UI from `web/`. Endpoints: `/health`, `/status`, `/block/<h>`, `/tx/<h>/<i>`, `/mempool`, `/events`, `/wallet/*`, `/tx/submit`.
- `stratum-serve` — SV2 pool endpoint (async tokio I/O, bounded concurrent sessions).
- `stratum-mine` — worker client.

### Storage contracts (all `redb`)

- Runtime archive DB: ordered blocks by height + hash index.
- Runtime state DB: network id, tip, UTXO snapshot, height→hash vector.
- Peer book DB, mempool snapshot DB, pool ledger DB (rounds/shares/worker accruals/payouts).

When you modify a storage schema, also update the reindex path (`reindex-runtime` subcommand) and the persistence-snapshot tests.

## Configuration model

Networks are config-first. `config/{devnet,testnet,mainnet,fast-devnet,chain}.toml` define consensus, mempool, p2p, stratum, wallet, genesis, and address HRP. New networks are generated with:

```bash
cargo run -p scam-node -- config-scaffold --network-id <id> --hrp <hrp> --out config/<id>.toml [flags…]
```

`scam-node node --network <profile> --config <path>` always takes both — the profile selects defaults, the file overrides. Tests and runtime helpers expect the config to validate (`ChainConfig::validate`) before any chain operation.

## Local development helpers

- Single-purpose launchers: `scripts/run-node-only.sh`, `scripts/run-miner.sh`, `scripts/run-node-miner.sh` (each with `start|stop|status|logs`; Windows `.bat` equivalents present).
- Multi-node lab: `scripts/local-multinode.sh up|status|down`; full lab with UI: `scripts/local-test-lab.sh up`.
- E2E flow check: `scripts/local-e2e-flow.sh` (wallet-01 → wallet-02 across node-0/node-1, expects `[e2e] success`).
- Preset loader: `scripts/run-preset.sh <preset> up|down` (presets in `scripts/presets/*.env`).
- Easy wrapper: `scripts/scam-easy.sh {node|relay|rpc|pool|miner}`.

## CI workflows (`.github/workflows/`)

- `ci.yml` — fmt/check/test (with the split for `scam-node`)/clippy, then `sv2-conformance-matrix.sh`.
- `mutation.yml` — manual dispatch with stage/timeout/shard/iterate knobs.
- `release-build.yml` — triggered by workspace version bumps on `master`; uploads `scam-node-linux-x86_64`, `scam-node-windows-x86_64.exe`, `scam-node-macos-aarch64` (macOS x86_64 is cross-compiled from the ARM64 runner — see recent commits).
- `sv2-release-gate.yml`, `sv2-external-interop.yml` — SV2 gate checks.

## Conventions worth following

- Workspace deps are pinned in the root `Cargo.toml` `[workspace.dependencies]`; per-crate `Cargo.toml` files use `<dep>.workspace = true`. Add new shared deps at the workspace root.
- The codebase uses Rust 2024 edition (`edition = "2024"`).
- `p2p` has a Windows-only conditional dep (`minisketch-rs` is `cfg(not(windows))`) — keep Windows compatibility in mind when touching erlay paths.
- Tokio is used with the multi-thread runtime; sync + async code paths coexist in `p2p::transport` and `stratum` (both blocking and `_async` variants of the same helpers). When adding a new transport helper, mirror both.

## Documentation map (`docs/`)

When you need deeper context, prefer these over re-reading code:

- `OPERATOR_RUNBOOK.md`, `USER_DEPLOYMENT_GUIDE.md` — runtime operations.
- `METHODICAL_MANUAL.md` + `manual/FUNCTION_INVENTORY.md` — generated function-by-function map.
- `MEMPOOL_THREAT_MODEL.md`, `TESTING_STRATEGY.md` — invariants and test rationale.
- `STRATUM_SV2_NOTES.md`, `SV2_ROLE_INTERFACES.md`, `SV2_POOL_GRADE_GAP.md`, `SV2_INTEROP_MATRIX.md` — SV2 implementation state and gap tracking.
- `FORKING_GUIDE.md` — full path for creating a new network from scratch.
- `WEB_CONSOLE.md` — `web/` UI + RPC contract.
- `agent/STATE.md` — most recent hardening notes (mutation/test deltas); useful to read when picking up where prior work stopped.
