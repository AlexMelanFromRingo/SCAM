# Mutation Report Actions (2026-02-13)

Source: `target/mutants/mutants.out/outcomes.json`  
Run window: `2026-02-13T16:10:10Z` -> `2026-02-13T17:09:00Z`

## Snapshot

- Total mutants: `1614`
- Caught: `630`
- Missed: `764`
- Timeout: `10`
- Unviable: `210`

## Priority Fix List

## P0: Consensus / Safety / Infinite-Loop Risk

- [ ] Add explicit tests for `merkle_root` termination and correctness on odd/even leaf counts (`crates/core/src/merkle.rs`).
- [ ] Add regression tests for replacement graph traversal termination in `Mempool::collect_replacement_set` (`crates/mempool/src/lib.rs`).
- [ ] Add regression tests for CPFP package traversal termination in `build_cpfp_package` (`crates/miner/src/lib.rs`).
- [ ] Add boundary tests for `ChainRuntime::expected_target_for_next_block` math and branch conditions (`crates/chain/src/lib.rs`).
- [ ] Add strict branch/boundary tests for `retarget_next`, `lwma_next`, `asert_next` (`crates/consensus/src/difficulty.rs`).
- [ ] Add negative-path tests for `validate_contextual_timestamps` and block acceptance/rejection toggles (`crates/chain/src/lib.rs`).

## P1: Stratum / P2P Protocol Robustness

- [ ] Expand `read_frame`/`read_frame_async` tests for malformed headers, type mismatch, zero/oversized payload, trailing bytes (`crates/stratum/src/lib.rs`).
- [ ] Add tests for `Sv2Session::install_job` capacity/eviction boundaries and job cache invariants (`crates/stratum/src/lib.rs`).
- [ ] Add tests for `Sv2Session::record_share_timestamp` VarDiff retarget boundaries (`crates/stratum/src/lib.rs`).
- [ ] Add tests that fail if `SecureSv2Transport::write_message_async` is a no-op (`crates/stratum/src/lib.rs`).
- [ ] Add async transport contract tests that fail if `send_message_async` does not write bytes (`crates/p2p/src/transport.rs`).
- [ ] Add richer interop assertions around `run_sv2_conformance` message sequence and error paths (`crates/node/src/main.rs`).

## P2: Node/RPC/Wallet Path Coverage

- [ ] Add focused tests for `run_rpc_serve` parser/dispatch/error branches (`crates/node/src/main.rs`).
- [ ] Add tests for `read_http_request` invalid method/header/content-length combinations (`crates/node/src/main.rs`).
- [ ] Add tests for `wallet_balance_response` / `run_wallet` edge cases (empty UTXO, mismatched HRP/network, decode errors).
- [ ] Add tests for `run_stratum_serve` and `run_stratum_mine` config validation branches.
- [ ] Add tests for static asset helpers (`guess_content_type`, `try_serve_ui_asset`) including unknown suffix and traversal rejection.

## P3: Core Utility Gaps

- [ ] Add stronger tests for `ChainConfig::validate` cross-field invariants (`crates/core/src/config.rs`).
- [ ] Add mutation-killing tests for `Encoder::write_varint` branch thresholds (`crates/core/src/codec.rs`).
- [ ] Add tests for `types.rs` arithmetic/overflow/signature edge conditions missed by current suite.
- [ ] Add tests for `wallet/src/qr.rs::render_ascii_qr` output invariants on minimal and high-density matrices.

## Timeout-Specific Actions

- [ ] Add explicit max-iteration guards (test-side or helper-side) for loops touched by timeout mutants:
- `core::merkle_root`
- `mempool::collect_replacement_set`
- `miner::build_cpfp_package`
- [ ] Reduce mutation flakiness by isolating long-running integration tests from unit mutation targets where possible.

## Execution Order (After Repo Publish)

- [ ] Stage 1: close all P0 items and re-run mutation on `core/consensus/chain/mempool/miner`.
- [ ] Stage 2: close P1 items and re-run mutation on `stratum/p2p/node` protocol subset.
- [ ] Stage 3: close P2/P3 items and run full workspace mutation baseline again.

