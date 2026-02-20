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

- [x] Add explicit tests for `merkle_root` termination and correctness on odd/even leaf counts (`crates/core/src/merkle.rs`).
- [x] Add regression tests for replacement graph traversal termination in `Mempool::collect_replacement_set` (`crates/mempool/src/lib.rs`).
- [x] Add regression tests for CPFP package traversal termination in `build_cpfp_package` (`crates/miner/src/lib.rs`).
- [x] Add boundary tests for `ChainRuntime::expected_target_for_next_block` math and branch conditions (`crates/chain/src/lib.rs`).
- [x] Add strict branch/boundary tests for `retarget_next`, `lwma_next`, `asert_next` (`crates/consensus/src/difficulty.rs`).
- [x] Add negative-path tests for `validate_contextual_timestamps` and block acceptance/rejection toggles (`crates/chain/src/lib.rs`).

## P1: Stratum / P2P Protocol Robustness

- [x] Expand `read_frame`/`read_frame_async` tests for malformed headers, type mismatch, zero/oversized payload, trailing bytes (`crates/stratum/src/lib.rs`).
- [x] Add tests for `Sv2Session::install_job` capacity/eviction boundaries and job cache invariants (`crates/stratum/src/lib.rs`).
- [x] Add tests for `Sv2Session::record_share_timestamp` VarDiff retarget boundaries (`crates/stratum/src/lib.rs`).
- [x] Add tests that fail if `SecureSv2Transport::write_message_async` is a no-op (`crates/stratum/src/lib.rs`).
- [x] Add async transport contract tests that fail if `send_message_async` does not write bytes (`crates/p2p/src/transport.rs`).
- [x] Add richer interop assertions around `run_sv2_conformance` message sequence and error paths (`crates/node/src/main.rs`).

## P2: Node/RPC/Wallet Path Coverage

- [x] Add focused tests for `run_rpc_serve` parser/dispatch/error branches (`crates/node/src/main.rs`).
- [x] Add tests for `read_http_request` invalid method/header/content-length combinations (`crates/node/src/main.rs`).
- [x] Add tests for `wallet_balance_response` / `run_wallet` edge cases (empty UTXO, mismatched HRP/network, decode errors).
- [x] Add tests for `run_stratum_serve` and `run_stratum_mine` config validation branches.
- [x] Add tests for static asset helpers (`guess_content_type`, `try_serve_ui_asset`) including unknown suffix and traversal rejection.

## P3: Core Utility Gaps

- [x] Add stronger tests for `ChainConfig::validate` cross-field invariants (`crates/core/src/config.rs`).
- [x] Add mutation-killing tests for `Encoder::write_varint` branch thresholds (`crates/core/src/codec.rs`).
- [x] Add tests for `types.rs` arithmetic/overflow/signature edge conditions missed by current suite.
- [x] Add tests for `wallet/src/qr.rs::render_ascii_qr` output invariants on minimal and high-density matrices.

## Timeout-Specific Actions

- [x] Add explicit max-iteration guards (test-side or helper-side) for loops touched by timeout mutants:
- `core::merkle_root`
- `mempool::collect_replacement_set`
- `miner::build_cpfp_package`
- [x] Reduce mutation flakiness by isolating long-running integration tests from unit mutation targets where possible.
  - Added package-scoped mutation mode in `scripts/mutation-baseline.sh` via `MUTATION_PACKAGES`.
  - Added staged runner `scripts/mutation-staged.sh` (`stage1`, `stage2`, `stage3`, `all`) to split heavy integration paths from core mutation loops.

## Execution Order (After Repo Publish)

- [x] Stage 1: close all P0 items and re-run mutation on `core/consensus/chain/mempool/miner`.
  - Re-run finished: `target/mutants-stage/stage1/mutants.out/outcomes.json`
  - Result snapshot (`2026-02-13T21:05:37Z`): `total=558`, `caught=440`, `missed=59`, `timeout=1`, `unviable=58`.
  - Current timeout hotspot: `crates/miner/src/lib.rs:308:16: delete ! in build_cpfp_package`.
- [ ] Stage 2: close P1 items and re-run mutation on `stratum/p2p/node` protocol subset.
- [ ] Stage 3: close P2/P3 items and run full workspace mutation baseline again.

## Addendum (2026-02-14)

- [x] Re-ran focused `p2p` mutation baseline after transport/discovery/sync hardening:
  - Command scope: `--package scam-p2p --file crates/p2p/src/{discovery,gossip,sync,transport,wire}.rs`
  - Result snapshot: `total=154`, `caught=123`, `missed=0`, `timeout=0`, `unviable=31`.
- [x] Re-ran focused `stratum` mutation baseline after frame/secure/noise hardening:
  - Command scope: `--package scam-stratum --file crates/stratum/src/lib.rs`
  - Result snapshot: `total=310`, `caught=238`, `missed=37`, `timeout=5`, `unviable=30`.
- [x] `stratum` misses were reduced (`89 -> 37`) and remaining misses are concentrated in:
  - vardiff threshold edge math (`Sv2Session::record_share_timestamp`),
  - noise sync/async branch guards and no-op replacements,
  - algebraically equivalent bitwise compose mutants (`|` vs `^` on non-overlapping shifted bytes),
  - constant-size arithmetic mutants in key-material array definitions.
- [x] Closed remaining focused `stratum` misses/timeouts:
  - Command scope: `--package scam-stratum --file crates/stratum/src/lib.rs`
  - Result snapshot: `total=261`, `caught=232`, `missed=0`, `timeout=0`, `unviable=29`.
- [ ] Re-ran full Stage 2 (`stratum+p2p+node`) after `stratum` closure:
  - Command scope: `scripts/mutation-staged.sh stage2`
  - Result snapshot: `total=847`, `caught=668`, `missed=47`, `timeout=0`, `unviable=132`.
  - Remaining misses are now concentrated in `crates/node/src/main.rs` (runtime sync-book/relay/rpc and auxiliary CLI paths).
- [ ] Re-ran full Stage 2 after first node hardening batch:
  - Command scope: `scripts/mutation-staged.sh stage2`
  - Result snapshot: `total=862`, `caught=690`, `missed=39`, `timeout=0`, `unviable=133`.
  - Remaining misses are concentrated in node runtime-network integration paths (`sync/relay/rpc/stratum`) and a few stream wrapper helpers.

## Addendum (2026-02-20)

- [x] Re-ran focused `rpc+wallet` mutation baseline after new vector/contract tests:
  - Command scope: `MUTATION_PACKAGES='scam-rpc scam-wallet' scripts/mutation-baseline.sh`
  - Result snapshot: `total=65`, `caught=52`, `missed=0`, `timeout=0`, `unviable=13`.
- [x] Closed last focused wallet miss at coinbase maturity boundary:
  - Added `rescan` boundary test: `coinbase_becomes_spendable_at_exact_maturity_boundary`.
- [x] Re-ran Stage 1 after miner/package comparator and CPFP hardening:
  - Command scope: `scripts/mutation-staged.sh stage1`
  - Result snapshot: `total=529`, `caught=471`, `missed=0`, `timeout=0`, `unviable=58`.

## Addendum (2026-02-21)

- [x] Collected latest CI mutation snapshots by stage after node/relay hardening waves:
  - Stage 1: `total=534`, `caught=472`, `missed=4`, `timeout=0`, `unviable=58`.
  - Stage 2: `total=875`, `caught=728`, `missed=11`, `timeout=10`, `unviable=126`.
  - Stage 3: `total=1497`, `caught=1250`, `missed=33`, `timeout=10`, `unviable=204`.
- [ ] Stage 2 rerun is still required on the newest realtime relay commit set (`unknown-parent recovery + mempool/rpc lock retry`) before closing Stage 2.
- [ ] Stage 3 rerun is still required after Stage 2 closes, because Stage 3 includes node/rpc/wallet surfaces touched by subsequent fixes.
- [ ] Remaining timeout focus:
  - `crates/node/src/main.rs` (`decode_optional_hex32`, `max_requests_reached`, `run_sv2_conformance`, `read_http_request` guards),
  - `crates/p2p/src/transport.rs::send_message`.

## Addendum (2026-02-20, live hardening pass)

- [x] Added relay stability regression for sustained short-lived sessions:
  - `relay_serve_handles_multiple_short_lived_handshakes_without_worker_errors`.
- [x] Added `/wallet/send` rejection coverage for invalid amount/hrp/insufficient funds and conflict retry path:
  - `run_rpc_serve_wallet_send_rejects_invalid_and_double_spend_paths`.
- [x] Strengthened `/events` contract test to assert required snapshot schema keys and heartbeat presence:
  - `run_rpc_serve_streams_event_snapshots`.
- [x] Added relay restart/rebroadcast regression:
  - `relay_restart_reloads_tip_and_rebroadcasts_unconfirmed_mempool_tx`.
- [ ] Stage 2/3 mutation reruns are still pending on top of this hardening pass.
