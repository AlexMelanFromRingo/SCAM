# SCAM Audit Notes (`audit/hardening-tui` branch)

Started: 2026-05-16. Auditor: Claude (Opus 4.7) — independent code review.
Scope: workspace as-of `master` HEAD (`23eec19`). Goal: surface real
consensus / DoS / cryptographic findings before they bite, using Bitcoin's
publicly documented vulnerability history as a checklist.

## How findings are scored

- **Severity**: how bad if exploited.
  - `critical` — consensus split, inflation, or key compromise.
  - `high` — node crash, persistent DoS, or fund loss in narrow cases.
  - `medium` — degraded service, log noise, defense-in-depth misses.
  - `low` — code quality / lint that could mask a future bug.
- **Status**: `open`, `fixed-in-branch`, `wontfix-with-rationale`.

The CVE references below describe the *Bitcoin* bug whose shape we are
checking SCAM against — they are not assertions that SCAM has the
identical bug; they say "we deliberately looked for this pattern".

---

## F-1. Baseline gate `clippy -D warnings` was red on current toolchain

- **Severity**: medium (CI hygiene; not exploitable).
- **Status**: fixed-in-branch.
- **Where**: `crates/p2p/src/discovery.rs`, `crates/mempool/src/lib.rs`,
  `crates/storage/src/lib.rs`, `crates/node/src/main.rs`.
- **Detail**: README and `docs/agent/STATE.md` claim full quality gate is
  green. On `rustc 1.95.0` (current stable) clippy fails with six
  `unnecessary_sort_by` / `explicit_into_iter_loop` warnings, which become
  errors under `-D warnings`. The project was previously validated on
  1.93.x; nothing automated tracked the regression.
- **Fix**: rewrote each call site to use `sort_by_key` / `sort_unstable_by_key`
  and dropped the redundant `.into_iter()`. CI passes again.
- **Recommendation**: pin the toolchain (rust-toolchain.toml) so version
  drift is no longer silent, and document the minimum supported rustc in
  `Cargo.toml` (`rust-version = "1.95"`).

---

## F-2. Block accepts duplicate txids (CVE-2012-2459 class)

- **Severity**: medium (defense in depth — currently masked by another check).
- **Status**: fixed-in-branch.
- **Where**: `crates/core/src/merkle.rs`, `crates/consensus/src/validate.rs`.
- **Reference**: Bitcoin CVE-2012-2459 — merkle root malleability via
  duplicated leaves.
- **Detail**: `merkle::merkle_root` duplicates the last leaf on odd count
  (`level.push(last)`). This is the *exact* pre-fix Bitcoin algorithm. A
  miner could compute a header for `[a, b, c]` and propagate `[a, b, c, c]`;
  both lists produce the same merkle root. SCAM survives only because the
  duplicate `c` re-spends `c`'s inputs, which `validate_non_coinbase_tx`
  catches as `DoubleSpendInBlock`. That is an incidental save, not a
  designed defense.
- **Concrete attack the incidental save does *not* cover**: nothing today,
  but any future code path that handles coinbase-only blocks or zero-input
  transactions would expose it. Belt and suspenders are cheap.
- **Fix**: add `BlockValidationError::DuplicateTxInBlock` and check
  `seen_txids` in `validate_block_basic` *before* the per-tx loop. Reject
  any block whose transaction list contains the same txid twice. Strictly
  stronger than the Bitcoin Core `fMutated` flag because it catches *any*
  duplicate txid, not only ones that emerged from odd-count duplication.
- **Test**: `merkle_duplicate_last_tx_attack_is_rejected`.

---

## F-3. `max_block_size` / `max_tx_size` not consensus-enforced

- **Severity**: high (consensus rule on paper, not in code — split risk).
- **Status**: fixed-in-branch.
- **Where**: `crates/consensus/src/validate.rs`, called from
  `crates/consensus/src/utxo.rs::validate_and_apply_block` and
  `crates/chain/src/lib.rs::submit_block`.
- **Reference**: Bitcoin's 1 MB block-size limit was both a consensus rule
  *and* enforced at validation. SCAM declares the limit only in
  `ChainConfig` and never reads it during block validation. Any peer that
  produced a 10 MB block would be accepted by the network.
- **Detail**: `ChainConfig { max_block_size, max_tx_size }` exists and the
  CLI exposes flags for it, but `grep` across `consensus/`, `chain/`,
  `mempool/`, and `node/main.rs` shows no path that compares
  `bincode::serialize(&block).len()` (or
  `tx.encode_for_hash().len()`) to either bound during validation. The
  only user is fee-rate math in mempool.
- **Fix**: thread the relevant limits through `validate_block_basic` and
  `validate_and_apply_block`, and reject the block before any heavy work
  (signature verification) if either bound is exceeded. New error variants
  `BlockTooLarge` / `TxTooLarge` keep the rejection reason actionable for
  ops. Existing call sites are updated to pass the live `ChainConfig`
  limits.
- **Tests**:
  - `oversize_block_is_rejected`
  - `oversize_tx_is_rejected`
- **Migration note**: existing devnet/testnet blocks are small (well
  under 1 MB defaults), so enabling the check is a no-op on running
  clusters. Pre-mainnet networks should publish the agreed limits in
  their config and re-validate.

---

## F-4. Status / docs claim a green mutation gate that no test now enforces

- **Severity**: low (process risk).
- **Status**: noted, no code change.
- **Detail**: `docs/RELEASE_STATUS.md` and `docs/agent/STATE.md` claim
  `stage3` mutation closure with `0 missed`. Re-running it is hours-long
  and out of scope for this branch, but the *claim* of completion was
  produced before the F-1 lint regression and is therefore stale.
- **Recommendation**: mark the existing reports with a "last verified on
  commit X" line, and have the mutation workflow add the commit SHA to its
  artifact path.

---

## F-7. Mempool admits arbitrary-size txs (anti-DoS)

- **Severity**: medium (DoS — bounded by `max_mempool_txs * tx_size`).
- **Status**: fixed-in-branch (opt-in via new setter).
- **Where**: `crates/mempool/src/lib.rs::insert_with_fee`.
- **Detail**: `insert_with_fee` computed `tx.encode_for_hash().len()` only for
  fee math; nothing rejected a tx that exceeded the configured
  `max_tx_size`. Worst case before fix: `max_mempool_txs` (default 50,000)
  × arbitrary bytes = unbounded RAM. The consensus-level check from F-3
  catches it at block validation, but a peer can still propagate fat txs
  and force every honest node to hold them in mempool.
- **Fix**: added `Mempool::set_max_tx_bytes(Option<usize>)` setter and a
  new `MempoolError::TxTooLarge` variant. When a cap is set, `insert_with_fee`
  rejects oversize txs *before* any work, including before fee math.
  Backwards compatible — the default is `None` (unchanged behavior). Live
  call sites (relay/rpc/stratum runtimes) should call the setter with
  `cfg.max_tx_size as usize` at startup; tests that pass raw values into
  `Mempool::with_policy` are unaffected.
- **Tests**:
  - `oversize_tx_is_rejected_at_admission`
  - `no_size_cap_means_unbounded`
- **TODO**: wire the setter into `crates/node/src/main.rs` mempool
  construction helpers. This is queued under task #8 because the live
  paths use multiple constructors that should be centralized.

---

## F-5. RPC server has no authentication, CORS, or origin check

- **Severity**: medium for prod; low for dev (binds to `127.0.0.1`).
- **Status**: noted, no code change (existing security boundary is
  documented in the README; deferred to operator runbook).
- **Where**: `crates/node/src/main.rs::run_rpc_serve_inner_axum` and
  the legacy handler.
- **Detail**: there is no `tower_http::cors::CorsLayer`, no
  bearer/basic-auth check, and no Origin/Host validation on any
  `/wallet/*`, `/tx/submit`, or other state-mutating route. The current
  safety boundary is the bind address (`127.0.0.1:18080` by default).
  Anyone able to send a `POST` to the loopback address — including a
  browser tab on the same host via a misconfigured proxy or a malicious
  page using DNS rebinding — can drain `/wallet/send` if a mnemonic is
  presented in the body. The web console assumes loopback.
- **Recommendation** (not implemented in this branch — design decision):
  1. Add `Host` header allow-list (reject anything that is not
     `127.0.0.1[:port]` or `localhost[:port]`) — defeats DNS rebinding.
  2. Add an optional `--rpc-auth-token` whose value must appear in an
     `Authorization: Bearer` header for `POST` routes.
  3. Document loud-and-clear in `WEB_CONSOLE.md` that exposing RPC on a
     non-loopback bind without auth is unsafe.

---

## F-6. Notes on places that already do the right thing

Recording these so future audits know the surface was checked:

- `validate_non_coinbase_tx` uses `u128` accumulators with `checked_add`
  for input/output sums, fees, and coinbase reward (`utxo.rs:243-245`,
  `66-104`). The CVE-2010-5139 / "value overflow" shape is closed.
- Cross-tx double-spend within a block is detected via the shared
  `spent_in_block: HashSet<OutPoint>` (`utxo.rs:173`). This is the
  CVE-2018-17144 fix — implemented correctly.
- Signing digest is domain-separated by `chain_domain`
  (`types.rs:79-81`) → replay across networks is rejected (test:
  `signature_replay_across_chain_domains_is_rejected`).
- Coinbase maturity is checked against `created_height + maturity`
  (`utxo.rs:187-195`).
- Schnorr signatures use libsecp256k1's `verify_schnorr`, which
  enforces BIP340-style serialization (64-byte fixed length, lift-x).
- TUI HTTP client caps response size and rejects chunked encoding
  (`crates/tui/src/http.rs`).

---

## F-8. P2P transport posture — checked, no findings to fix

- **Severity**: n/a (audit observation).
- **Status**: clean.
- **Where**: `crates/p2p/src/transport.rs`, `crates/p2p/src/wire.rs`.
- **Detail**: walked the framing/handshake path against the standard
  network DoS checklist:
  - Magic check before length-decoding: yes (`ScamWireCodec::decode`).
  - Size cap enforced *before* allocation: yes — `read_message_async`
    rejects oversize `payload_len` prior to `vec![0u8; payload_len]`.
  - Bincode decode uses `with_limit(...)` *and* `reject_trailing_bytes()`:
    yes (`wire.rs::decode_message`). Both are belt-and-suspenders for
    fuzz robustness.
  - Consensus fingerprint validated by caller in
    `client_handshake_async` flow (`main.rs:4946`,
    `ensure_consensus_fingerprint_match`).
  - Connect + handshake wrapped in `tokio::time::timeout` in the live
    feeler/outbound path (`main.rs:9520, 9541`).
- The default `max_message_size` is `8 * 1024 * 1024`. With ~1000 peers
  that's an 8 GB *peak* worst-case allocation if everyone sends max-size
  frames simultaneously. Bounded but worth a per-peer in-flight budget
  if SCAM ever opens to a large peer set; out of scope here.

---

## F-9. Wallet vault + signer posture — checked, no findings to fix

- **Severity**: n/a (audit observation).
- **Status**: clean.
- **Where**: `crates/wallet/src/{signer.rs,vault.rs}`.
- **Detail**:
  - `sign_digest` uses `sign_schnorr_no_aux_rand` → deterministic BIP340
    nonce (no malleability from RNG, no side-channel on aux randomness).
  - `verify_digest` parses a strict 64-byte Schnorr signature
    (`Signature::from_slice`) and uses `verify_schnorr` against the
    x-only pubkey — no `0x02/0x03` parity ambiguity.
  - `Message::from_digest_slice(&digest32)` enforces 32-byte input.
  - Argon2id at m=32 MiB / t=2 / p=1. Above OWASP 2023 minimum
    (m=19 MiB / t=2 / p=1).
  - XChaCha20Poly1305 with 24-byte nonce from `OsRng` per encryption —
    no nonce-reuse risk.
  - Vault version + KDF algorithm name pinned and verified on decrypt.
- Minor: `SecretKey` and `secret_key_bytes() -> [u8; 32]` do not zeroize
  on drop. Acceptable for an in-process wallet but worth noting for
  threat models that include process-memory forensics.

---

## F-10. XSS via unescaped RPC payload in `renderLatestBlocks`

- **Severity**: medium (DNS rebinding + browser cache turns an RPC bug
  into in-browser code execution under loopback origin).
- **Status**: fixed-in-branch.
- **Where**: `web/app.js::renderLatestBlocks`.
- **Detail**: every other render path in `web/app.js` walks through
  `escapeHtml(...)` before inlining into innerHTML. The
  `renderLatestBlocks` loop missed it for `block.hash`, `block.target`,
  `block.height`, `block.tx_count`, `block.timestamp`. The hash and
  target fields go into both the cell text and the `title=""`
  attribute, giving an attacker the easier attribute-injection variant
  too. The path is reached on every dashboard refresh.
- **Threat**: F-5 already noted that the RPC binds to localhost. A
  malicious RPC mock under a DNS-rebound hostname (or a same-host
  process bound to a stale port) can return crafted JSON; the page
  is loaded over `http://127.0.0.1:18080`, so the script runs with
  same-origin trust over every other localhost service the user has
  open. Defense-in-depth: never inline RPC payload bytes into HTML.
- **Fix**: wrap every interpolated field in `escapeHtml(...)`. Added
  a comment in the code so future contributors don't regress it.

---

## Items deferred (not closed, just out of scope for this branch)

- Stratum / SV2 transport: cancel-safety review of the async session
  loop; per-message size cap on the noise_xx side; rekey-interval
  edge cases.
- Wallet vault: Argon2 parameter selection (m_cost / t_cost) review.
- Storage: redb transaction boundary review (concurrent
  reindex/relay/rpc paths can hold conflicting writes).
- Eclipse-attack hardening: outbound peer-bucket distribution review.
- BIP155 (addr v2) — SCAM uses its own address codec; out of scope.
- `web/app.js` — XSS posture spot-checked (uses `escapeHtml` on every
  user-controlled value rendered into `innerHTML`); full pass deferred.
