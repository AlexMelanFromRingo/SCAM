# Agent State (Recovery Notes)

Last updated: 2026-03-07

## Current reliable baseline
- `cargo fmt --all`: pass.
- `cargo check --workspace`: pass.
- `cargo test --workspace --all-targets`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- `cargo test -p scam-node --bin scam-node -- --test-threads=1`: pass (308 tests).

## Today’s hardening batch (uncommitted at this note update)
- File: `crates/node/src/main.rs`
- Added resilient RPC DB retry knobs:
  - `rpc_db_retry_attempts()`
  - `rpc_db_retry_backoff_ms()`
- Added explicit lock-fallback guards for `/mempool` serving:
  - `mempool_summary_should_fallback_on_error()`
  - `mempool_cleanup_persist_is_fatal()`
- Switched submit path to runtime-cached validation for RPC handlers:
  - new `submit_tx_via_mempool_db_for_runtime()`
  - new `submit_tx_via_mempool_db_for_runtime_with_retry()`
  - Axum and legacy `/wallet/send` + `/tx/submit` now avoid runtime DB reopen on every submit.
- Increased retry usage in wallet reserved-outpoint load path.
- Added/extended tests:
  - helper guard invariants for retry+fallback logic
  - runtime-based submit path coverage

## Mutation note
- Focused mutation run for new RPC retry helpers was started and then interrupted intentionally.
- Partial output showed misses concentrated in retry-helper boundary functions.
- Action item before full staged rerun: finalize targeted mutation closure for the new helper functions, then rerun Stage2 and Stage3.

## Immediate next actions
1. Commit current RPC hardening batch.
2. Run focused mutation on changed node functions (retry/fallback/submit-runtime).
3. Close misses with narrow tests (no broad refactor), then rerun Stage2.
4. After Stage2 is clean, rerun Stage3 and only then mark RC2 gate.
