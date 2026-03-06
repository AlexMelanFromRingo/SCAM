# Agent Autonomous TODO

## Scope
- Close mutation stage2 misses (`scam-stratum`, `scam-p2p`, `scam-node`) without regressions.
- Keep battle-tested migration track active: `SOCKS5`, `HTTP`, `wire/codec`.
- Gate every phase with `cargo fmt`, `cargo check`, `cargo test`, `cargo clippy`.

## Phase Plan

### Phase A: Stage2 mutation stabilization
- [x] Group current stage2 misses by function/module.
- [x] Strengthen unit tests for `p2p::discovery` and `p2p::gossip` (boundaries + branch behavior).
- [x] Strengthen `node` tests for env/policy/socks/diffusion/relay boundaries and flaky paths.
- [x] Run targeted mutation loop for `scam-p2p` discovery/gossip until zero misses.
- [x] Run full stage2 mutation (`scam-stratum`, `scam-p2p`, `scam-node`) and close remaining misses.
- [x] Re-run stage2 mutation after fixes to confirm stable zero-miss/no-timeout state.

### Phase B: Battle-tested transport/protocol migration
- [x] Migrate async SOCKS5 connect path to `tokio-socks` (remove hand-rolled async dial logic).
- [x] Migrate `rpc-serve` HTTP path to `hyper`/`axum` while preserving existing route contracts/tests.
  - `axum` backend now implements full route parity for RPC GET/POST endpoints, SSE `/events`, pool routes, and UI asset fallback behavior.
  - `SCAM_RPC_HTTP_BACKEND=axum` remains available for rollout control; legacy path is retained only as compatibility backend.
- [x] Move wire framing onto battle-tested codec path (`tokio-util` codec) with strict size limits (async path).
- [x] Keep compatibility tests for version/handshake/frame boundary behavior.
  - Verified via `cargo test -p scam-p2p` (`transport::tests::*` frame/size/handshake boundaries)
    and `cargo test -p scam-node --bin scam-node -- --test-threads=1`
    (`sv2_conformance*`, relay handshake/timeouts, rpc route boundary paths).

### Phase C: Verification gates (mandatory after each sub-phase)
- [x] `cargo fmt --all`
- [x] `cargo check --workspace`
- [x] `cargo test --workspace`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] Mutation gate re-check for stage2.

### Phase D: Local commit policy (no push)
- [x] Commit 1: Stage2 mutation fixes (`p2p/node`).
  - `7f37a2d Harden stage2 mutation guards for node and p2p`
- [x] Commit 2: HTTP migration (`hyper`/`axum`) + route tests.
- [x] Commit 3: wire/codec migration + framing tests.
  - `db184e1 Finalize axum rpc backend parity and harden p2p wire codec`
- [x] Commit 4: final verification gate + docs status update.
  - Verification gate (non-mutation) completed on current HEAD:
    `cargo fmt --all -- --check`,
    `cargo check --workspace`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`.

## Current status snapshot
- `p2p` targeted mutation loop for `discovery/gossip`: closed (0 misses in scoped run).
- `rpc-serve` axum path: full route parity done, SSE and UI fallback included.
- `p2p::transport` async frame path now uses `tokio-util` codec + strict magic/size checks.
- Stage2 mutation closure: complete (`0 missed`, `0 timeout` on closure reruns).
- Stage3 full workspace mutation closure: complete (`0 missed`, `0 timeout` on final rerun).
