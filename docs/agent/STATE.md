# Agent State (Recovery Notes)

Last updated: 2026-03-07

## Current reliable baseline
- `cargo fmt --all`: pass.
- `cargo check --workspace`: pass.
- `cargo test --workspace --all-targets`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- `cargo test -p scam-node --bin scam-node -- --test-threads=1`: pass (310 tests).

## Today’s hardening batch (committed)
- Commit `543b7ee`
  - File: `crates/node/src/main.rs`
  - Added resilient RPC DB retry knobs:
    - `rpc_db_retry_attempts()`
    - `rpc_db_retry_backoff_ms()`
  - Added explicit lock-fallback guards for `/mempool` serving:
    - `mempool_summary_should_fallback_on_error()`
    - `mempool_cleanup_persist_is_fatal()`
  - Switched submit path to runtime-cached validation for RPC handlers:
    - `submit_tx_via_mempool_db_for_runtime()`
    - `submit_tx_via_mempool_db_for_runtime_with_retry()`
    - Axum and legacy `/wallet/send` + `/tx/submit` avoid runtime DB reopen per request.
  - Increased retry usage in wallet reserved-outpoint load path.
  - Added/extended tests for helper guard invariants and runtime-based submit path.

- Commit `59a07ad`
  - File: `crates/node/src/main.rs`
  - Closed fresh stage2 mutation survivors around stale mempool cleanup accounting:
    - `remove_mempool_txs_with_missing_inputs_removes_stale_dependency_chain`
    - `cleanup_mempool_against_chain_returns_total_removed_for_stale_dependency_chain`
  - Validation:
    - new tests pass individually and in full `scam-node` suite
    - targeted mutation scope `(remove_mempool_txs_with_missing_inputs|cleanup_mempool_against_chain)` => `5 caught, 0 missed`.

## Mutation note
- Focused mutation scope for RPC retry helpers was completed: no misses/timeouts in that focused set.
- Full stage2 iterate rerun is in progress to discover next survivors after the two cleanup-count fixes above.

## Immediate next actions
1. Finish current stage2 iterate pass and collect only new survivors.
2. Close survivors in narrow slices (tests first, then minimal code change).
3. Re-run stage2 iterate until clean.
4. Re-run stage3 and only then mark RC2 gate.
