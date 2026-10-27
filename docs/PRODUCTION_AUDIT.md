# Production-readiness audit (2026-10-27)

Source of truth for this audit pass. Every finding below was confirmed by
reading code (docs were treated as unverified claims). `main.rs` means
`crates/node/src/main.rs`; its line numbers drift as code changes, so treat
them as search hints.

Status: `fixed` (code + regression test in tree) · `in-progress` · `open` ·
`deferred` (needs a design decision or is out of scope, see note).

Baseline at start: `fmt`/`clippy -D warnings`/`cargo test --workspace
--exclude scam-node` green on `audit/hardening-tui` @ `f81eeb3`.

## Consensus / chain runtime

| ID | Sev | Finding | Where | Status |
|---|---|---|---|---|
| C1 | critical | BIP30 class: a block may recreate an outpoint that is still unspent (identical coinbase ⇒ same txid). `staged.insert` overwrote the victim UTXO (resetting maturity); disconnecting the copy deleted the outpoint ⇒ nodes that reorged diverge. | `consensus/src/utxo.rs` apply | fixed (`OutputAlreadyExists`) |
| C2 | critical | Side-branch blocks are stored after PoW is checked only against their *own* claimed target. `Target::MAX` side blocks cost nothing ⇒ unbounded memory (blocks held in RAM). | `chain/src/lib.rs::submit_block` | fixed (branch-aware expected target before storing) |
| C3 | critical | `ChainRuntime::collect_block_undo` looks up inputs only in the pre-block UTXO set ⇒ any block where a tx spends an output of an earlier tx in the same block is rejected (`MissingUndoSpentUtxo`); disconnect had the mirror bug. The CPFP-aware template builder produces exactly such blocks ⇒ pool blocks rejected. | `chain/src/lib.rs` | fixed (undo built by consensus apply; test with CPFP-shaped block + reorg) |
| C4 | high | Multisig: duplicate-key check compares 33-byte encodings, but BIP340 verifies x-only. `02‖X` and `03‖X` let one signer fill two slots. | `consensus/src/multisig.rs` | fixed |
| C5 | medium | Multisig verify tried every sig against every key (k·n Schnorr verifications, non-canonical witness). | `consensus/src/multisig.rs` | fixed (descriptor order, ≤ n verifications) |
| C6 | high | ASERT uses `f64::powf` in consensus ⇒ libm differences across platforms can split the chain. | `consensus/src/difficulty.rs` | fixed (integer aserti3-2d cubic) |
| C7 | high | LWMA: pairwise solvetimes floored at 1 ⇒ alternating future/past timestamps record `6T+1` per `2T`, difficulty ratchets down ~3×. Mainnet uses LWMA. | `consensus/src/difficulty.rs::lwma_next` | fixed (zawy previous-max handling) |
| C8 | medium | Windowed retarget uses disjoint windows ⇒ timewarp gap (fast-devnet). | `chain/src/lib.rs` | fixed (overlapping windows) |
| C9 | high | Every tip-extending block cloned the full UTXO set twice, all undo data and `main_chain` ⇒ O(state) per block. | `chain/src/lib.rs`, `consensus/src/utxo.rs` | fixed (overlay apply, tip fast path, journaled reorg rollback) |
| C10 | medium | `undo_data` kept forever; side branches never pruned. | `chain/src/lib.rs` | fixed (`MAX_REORG_DEPTH`=720, prune every 64 tip changes) |
| C11 | medium | No invalid-block cache ⇒ each descendant of a bad side block retriggers a full failing reorg. | `chain/src/lib.rs` | fixed |
| C12 | medium | No max reorg depth. | `chain/src/lib.rs` | fixed (720 blocks; deeper reorg needs operator resync) |
| C13 | medium | Local replay (`from_ordered_blocks`) applies the wall-clock "≤ now+2h" rule ⇒ host with a clock behind cannot restart; reindex cannot recover. | `chain/src/lib.rs` | fixed |
| C14 | high | Local miner coinbase tag has no height (`mine-once`, mining loop) ⇒ identical coinbases (now invalid under C1). | `main.rs::build_coinbase_tx` callers | fixed (height in tag; reproduced by soak tests) |
| C15 | high | Stratum template and other node paths use `cfg.block_subsidy` instead of `subsidy_at_height(h)` ⇒ after the first halving every pool block is invalid. | `main.rs` (~20 non-test sites) | fixed (local miner, stratum template, TP request, round reward) |
| C16 | medium | P2P consensus fingerprint omits `halving_interval_blocks`, `tail_emission`, versionbits params ⇒ peers with different monetary policy handshake and fork later. | `main.rs::consensus_fingerprint` | fixed (fingerprint v2) |
| C17 | low | BIP113 not applied: absolute `lock_time` compared to header time, not MTP. | `consensus/src/utxo.rs` | deferred |
| C18 | low | BIP34 (height in coinbase) not a consensus rule; C1 covers safety. | consensus | deferred |
| C20 | low | CSV deviates from BIP68 by one: height locks need `spend > created + value` (BIP68: `>=`), time locks compare with the creating block's own header time (BIP68: MTP of its parent). Deterministic, not exploitable; docs claim "verbatim BIP68". | `consensus/src/csv.rs` | deferred (document or align before mainnet) |
| C19 | info | `config/mainnet.toml` has halvings disabled ⇒ constant 50/block forever. Policy decision for the owner. | config | deferred (owner decision) |

## Mempool / block templates

| ID | Sev | Finding | Where | Status |
|---|---|---|---|---|
| M1 | critical | P2P tx admission skips signature, pubkey-hash, maturity, locktime, CSV checks (RPC path has them). Forged spends of anyone's UTXO enter mempool, pin real spends, poison every template. | `main.rs::admit_peer_tx_into_relay` → `mempool::validate_transaction_for_mempool` | fixed (shared `validate_tx_for_next_block`) |
| M2 | critical | No admission path checks BIP68 sequence locks ⇒ one locked tx makes every template invalid for up to 65535 blocks. | `main.rs::validate_tx_for_local_admission` | fixed |
| M3 | medium | Admission requires 33-byte pubkey / 64-byte sig ⇒ multisig spends can never be relayed or submitted. | `main.rs::validate_tx_for_local_admission` | fixed |
| M4 | critical | Template builder caps tx *count* only (50k) ⇒ >1 MB templates are consensus-invalid under normal load; package selection is O(N³) under the stratum lock. | `miner/src/lib.rs::build_template_from_mempool` | fixed (ancestor-feerate selection, byte budget) |
| M5 | high | Templates are never validated against the chain before being mined. | `main.rs::RuntimeTemplateProvider::build_template` | fixed (`select_valid_block_transactions`, exact-fee coinbase) |
| M6 | high | `/tx/submit` stores caller-claimed fee (any value ≥ implied); sanitizer falls back to stored fee ⇒ eviction/priority gaming and `CoinbaseRewardTooHigh` pool blocks; the "rewrite coinbase and retry" path invalidates the PoW. | `main.rs` submit + `sanitize_template_mempool_fees` | fixed (actual fee only; sanitizer defers unresolved) — dead retry path left in place |
| M7 | high | Orphan pool: no per-tx byte cap (8 MiB × 5000), `insertion_order` never trimmed. | `mempool/src/lib.rs::OrphanPool` | fixed (16 MiB total cap, queue compaction; node checks max_tx_size before orphaning) |
| M8 | medium | Eviction/replacement can remove a parent while keeping (or admitting) its child. | `mempool/src/lib.rs` | fixed |
| M9 | medium | Replacement only needs +1 fee unit; per-peer replacement limit applied after insertion. | `mempool/src/lib.rs`, `main.rs` | partially fixed (BIP125 rule 4 incremental fee); rate-limit ordering open |
| M10 | low | Wallet default fee 1 < min relay; fee not size-based; amounts in atomic units unlabeled. | wallet/RPC/web | open |

## P2P / relay

| ID | Sev | Finding | Where | Status |
|---|---|---|---|---|
| P1 | critical | `handle_sketch` deserializes peer bytes into minisketch without checking length ⇒ C reads past the buffer (empty Vec ⇒ segfault). Role of round not checked. | `p2p/src/gossip.rs::handle_sketch` | fixed (exact `serialized_size` required) |
| P2 | critical | Relay GetData path has no item cap and clones a block per (duplicate) hash under the global mutex ⇒ OOM. | `main.rs::relay_collect_getdata_from_memory` | fixed (dedup, item cap, 16 MiB/16 archive blocks per request) |
| P3 | critical | Compact block: `vec![None; tx_count]` sized by peer before checks (u32::MAX ⇒ abort); per-slot full mempool sort; `pending_compact_blocks` unbounded, filled before PoW check. | `main.rs` compact-block handling | fixed (count bound + consistency, header PoW/target gate, short-id index, 64 pending cap) |
| P4 | high | Finished inbound sessions never reaped from `JoinSet`; errors embed attacker payload (`{other:?}` of 8 MiB msg). | `main.rs` relay accept loop, `p2p/src/transport.rs` | fixed (reaped with `try_join_next`; logged detail truncated) |
| P5 | high | `timeout(read_message_async)` is not cancel-safe ⇒ partial frame lost, stream desync; >250 ms block transfer never succeeds. | `main.rs` relay session read loop | fixed (`FrameReader`, async + blocking) |
| P6 | high | Bans keyed by per-connection id / `ip:port`; no ban check on accept; invalid blocks/txs not penalized; Addr re-announce lowers ban score. | `gossip.rs`, `main.rs` | fixed (24 h IP bans checked at accept; only context-free invalid data punished; context-dependent tx failures dropped quietly) |
| P7 | high | Addr: unbounded peer book, no address validation/length cap, stamps `max(seen, now)`, string-sorted truncation ⇒ eclipse aid; O(n²) rewrite per message. | `main.rs` addr handling | partially fixed (validation, timestamp clamp, keyed-random eviction); source-group bucketing and peer-book rewrite cost open |
| P8 | medium | Per-peer `known_inventory` unbounded. | `gossip.rs` | fixed (50k per peer, oldest evicted) |
| P9 | medium | O(chain)/O(mempool) work under the global mutex per message (GetHeaders clones all headers, mempool sorted per 250 ms poll). | `main.rs` | open |
| P10 | medium | Peer tip height trusted from Version/Inv/unchecked headers ⇒ forced outbound churn ("lag mode"). | `main.rs` | open |
| P11 | medium | `--max-clients N` is a lifetime connection limit; relay exits after N connections. | `main.rs` accept loop | open |
| P12 | medium | Compact short ids unsalted (8-byte txid prefix); no fallback to full block; BlockTxn accepted from any peer. | `main.rs` | open |
| P13 | low | Unpruned maps: `banned_peers`, `inbound_accept_history`, `peer_tip_by_address`. | `main.rs`, `gossip.rs` | partially fixed (`inbound_accept_history` pruned; `banned_ips` expire) |

## Storage / process model

| ID | Sev | Finding | Where | Status |
|---|---|---|---|---|
| S1 | critical | `stratum-serve` loads the chain once, never reloads, and persists its stale chain over the shared archive (temp+rename, no ancestry check); relay refresh adopts disk state without fork choice ⇒ chain rollback. | `main.rs` stratum persist / relay refresh | fixed (guarded write refuses stale writers via recorded tip work; refresh merges disk blocks through `submit_block`) — single-writer redesign still recommended |
| S2 | high | Relay drops the mutex between `submit_block` and persist; background refresh can reload in between and the session then persists the older chain. | `main.rs` relay session | mitigated (refresh now merges instead of replacing, so the new block survives) |
| S3 | high | Every tip change rewrites the entire archive (O(H²) bytes during sync). | `storage::save_chain_archive_db` callers | fixed (`persist_chain_archive_incremental_db`: one redb txn, only new blocks) |
| S4 | high | Every start/refresh replays all blocks with full signature checks (relay ~1 s after any write, RPC cache, each SSE conn, each payout). | `main.rs::load_runtime_from_db_or_genesis` | partially fixed (refresh reads tip meta, then only the tail, validating only unknown blocks); cold start still replays — persisted UTXO set needed |
| S5 | medium | Mempool DB: load-modify-rewrite from RPC, relay and stratum ⇒ lost updates; `GET /mempool` writes. | `main.rs` | open |
| S6 | medium | redb exclusive open per access; nested retry sleeps while holding locks / in async tasks. | `main.rs` | open |
| S7 | low | No on-disk schema version; `#[serde(default)]` useless under bincode. | `storage` | open |
| S8 | low | Temp files leaked on error; rename while temp DB still open. | `storage` | fixed for the runtime archive (no temp file anymore) |

## Stratum / pool

| ID | Sev | Finding | Where | Status |
|---|---|---|---|---|
| ST1 | critical | stratum-serve works on a stale tip forever (see S1); ledger never sees reorgs ⇒ orphaned rounds paid. | `main.rs` stratum | fixed (merge-refresh on every tip poll and before found-block validation); ledger reorg handling still open (see ST4/ST5) |
| ST2 | critical | Sanitizer uses claimed fee when parent not yet resolved (children first by feerate) ⇒ `CoinbaseRewardTooHigh`; retry path rewrites coinbase ⇒ PoW lost. | `main.rs` | fixed (see M6/M5) |
| ST3 | high | PPS credit fixed per share regardless of share difficulty; min share target = any hash; liability cap 0 = unlimited. | `main.rs` payout | fixed (credit scales with share expected hashes vs the hardest share target); liability cap default still 0 |
| ST4 | high | Payout txs pick the same pool coins; conflict outcome reported as success; txid recorded after broadcast ⇒ stuck or double payouts. | `main.rs::build_signed_transfer_tx` & payout loop | partially fixed (mempool-spent coins excluded, conflict outcome is a failure); txid-before-broadcast + stuck-payout expiry open |
| ST5 | high | PPLNS earnings recomputed from capped history but compared with lifetime paid ⇒ workers stop being paid. | `main.rs` payout | open — needs per-round credit snapshots persisted, i.e. a ledger schema version (S7) |
| ST6 | medium | Shares for old-tip jobs still credited; tip only rechecked on read timeout. | `stratum/src/lib.rs`, `main.rs` | fixed (share credited only if its job builds on the current — refreshed — tip) |
| ST7 | medium | Whole pool ledger DB rewritten per share. | `storage`, `main.rs` | open |
| ST8 | low | Stratum async read timeout not cancel-safe. | `main.rs` | open |
| ST9 | low | `stratum_secure_transport=false` on mainnet ⇒ payout address in plaintext. | `config/mainnet.toml` | open |

## RPC / wallet / web

| ID | Sev | Finding | Where | Status |
|---|---|---|---|---|
| R1 | high | `/tx/submit` trusts claimed fee (= M6); handlers ignore Content-Type ⇒ `text/plain` cross-site POST reaches it. | `main.rs` | fixed |
| R2 | high | Windows: UI file server `ui_dir.join("C:/…")` escapes the UI dir ⇒ arbitrary file read (vaults). | `main.rs::sanitize_ui_path` | fixed |
| R3 | high | `wallet secure-new/restore` silently overwrite an existing vault; write not atomic; default 0644. | `main.rs`, `wallet/src/vault.rs` | fixed (create_new + 0600 + fsync; `--force` = atomic replace) |
| R4 | high | `/wallet/*` take mnemonic+passphrase in the body, always enabled, no auth; Host allow-list passes behind a reverse proxy. | `main.rs` router | fixed (JSON-only POST, loopback Origin, optional bearer token required for non-loopback binds, `--disable-wallet-rpc`) |
| R5 | medium | Secrets only via CLI args (`ps`, shell history). | `main.rs::WalletCommand` | open |
| R6 | medium | RPC DoS: blocking work in async handlers under mutex; `/txid` full-chain scan; `/events` unlimited subscribers each reloading state; telemetry files never rotated. | `main.rs` | open |
| R7 | medium | Legacy RPC backend: no Host allow-list; `?` in accept loop kills server; selected by any non-"axum" env value. | `main.rs` | fixed (explicit `legacy` only; refuses non-loopback/auth configs) |
| R8 | medium | PSBT-lite signs a digest computed before `pubkey_compressed` is set to the descriptor ⇒ finalized tx invalid; chain domain not checked; no input values. | `wallet/src/psbt.rs` | fixed (descriptor filled at creation and checked on sign/finalize; CLI prints chain domain) — input values still absent |
| R11 | low | Web console: mnemonic fields autocomplete/spellcheck on; no CSP / X-Frame-Options; `apiBase` override from localStorage. | `web/` | fixed (no autocomplete/spellcheck on secrets, passphrases masked, CSP + X-Frame-Options + nosniff; CSP limits `connect-src` to loopback) |
| R12 | low | QR payment URI label not percent-encoded ⇒ parameter injection. | `wallet/src/qr.rs` | fixed |
| R13 | low | No zeroization of secrets; `json_error_body` does not escape control chars. | wallet, `main.rs` | partially fixed (JSON via serde); zeroization open |

## Behaviour changes operators must know

These fixes change consensus or operational behaviour. SCAM has no live
mainnet, so the consensus changes are made in place (no versionbits gate),
but **existing devnet/testnet chains and nodes must be upgraded together**:

- Consensus: blocks may not recreate an unspent outpoint (BIP30 rule);
  multisig keys must be distinct as x-only keys and signatures must follow
  descriptor order; LWMA ignores out-of-sequence timestamps; ASERT uses
  integer math (different, now platform-independent targets); windowed
  retarget measures from the previous window's last block. A chain built by
  older code can fail to replay — rebuild devnet/testnet data from genesis.
- P2P handshake fingerprint is `v2` (now covers halving/tail emission and
  versionbits); old and new nodes refuse each other.
- Reorganizations deeper than 720 blocks (`scam_chain::MAX_REORG_DEPTH`) are
  refused; a node stuck behind such a split must be resynced by an operator.
- Peers that send data invalid in every context (bad signature, wrong target,
  malformed frames) are banned by IP for 24 h.
- `/tx/submit` stores the transaction's real fee; a `fee` field that differs
  from it is rejected (send `0` or the exact fee).
- RPC: see the security model in `README.md` (JSON-only POST, loopback
  Origin, bearer token for non-loopback binds, `--disable-wallet-rpc`).
- `wallet secure-new|secure-restore` no longer overwrite an existing vault
  without `--force`.
- The runtime archive is written incrementally with recorded tip work; a
  process whose chain is behind the archive gets `StaleArchiveWriter` instead
  of overwriting it. Archives written by older versions are accepted.

## Verification of this pass (2026-10-28)

- `cargo fmt --all -- --check`, `cargo check --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo test --workspace --exclude scam-node`: 476 passed, 0 failed
  (baseline 463 before this pass's new tests).
- `cargo test -p scam-node --bin scam-node -- --test-threads=1`: 370 passed,
  0 failed (baseline 360); `--test cli_main`: 1 passed.
- `scripts/local-e2e-flow.sh` (release build, 2 nodes + miner): `[e2e]
  success` — wallet-01 → wallet-02 tx admitted on node-0, mined, propagated,
  credited on node-1; no new warnings in relay/rpc/stratum logs.
- Not run: mutation stages, fuzzing, multi-hour soak/WAN profiles.

## Fix order

1. Consensus/chain (C1–C16) — a bug here forks the network.
2. Template/mempool validity (M1–M6, ST2) — today any user can stall all mining.
3. Remote crash / OOM in P2P (P1–P5).
4. Process model (S1/ST1/S2), then RPC/wallet (R2–R4, R8).
5. Remaining medium/low items.
