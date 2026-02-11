# SCAM Implementation TODO (MVP but Production-Style Base)

Status: draft v1 (frozen decisions from user session on 2026-02-11)

## Progress Snapshot (2026-02-11)

- [x] Workspace crates created: `core`, `consensus`, `mempool`, `wallet`, `p2p`, `miner`, `storage`, `node`.
- [x] Core block/tx/header structures + deterministic serialization + BLAKE3 hash API.
- [x] PoW numeric target compare (`hash <= target`) implemented.
- [x] Dynamic difficulty retarget formula implemented (window/clamp from config).
- [x] Mempool conflict policy implemented (lower `txid` wins, descendants evicted on replacement).
- [x] Wallet basics implemented: mnemonic generation/restore, Schnorr sign/verify, Bech32m address, QR output.
- [x] UTXO block application implemented with signature checks, fee accounting, coinbase maturity.
- [x] P2P wire messages + gossip dedup engine (`inv/getdata/tx/block`) implemented.
- [x] P2P TCP transport framing + `version/verack` handshake + `ping/pong` + `getheaders/headers` demo implemented.
- [x] Miner template + nonce search loop implemented (`mine-once` CLI).
- [x] Chainstate snapshot save/load implemented.
- [x] redb-backed snapshot persistence implemented (`snapshot save-genesis-db` / `snapshot show-db`).
- [x] Reorg-safe best-chain selection by cumulative work implemented in chain runtime.
- [x] Minimal HTTP JSON RPC transport implemented (`scam-node rpc-serve`).
- [ ] Remaining major items: socketed p2p sync runtime beyond demo mode, persistent DB-backed node runtime.

## 1) Frozen Design Decisions

- Consensus: PoW.
- Hash algorithm: BLAKE3, 32-byte output (`Hash256`).
- Block validity rule: interpret block hash and target as unsigned 256-bit integers; valid when `hash <= target`.
- Target block time: `120` seconds.
- Difficulty adjustment window: `20` blocks (configurable constant).
- Reward model: fixed block subsidy (no hard cap by default).
- Double-spend mempool policy: for conflicting tx spending same outpoint, keep tx with lower numeric `txid` (BLAKE3 hash).
- Public key format at interfaces: compressed secp256k1 pubkey (33 bytes, `02/03 + x`).
- Signature scheme: Schnorr over secp256k1 (BIP340 style, x-only verification key internally).
- Address format: Bech32m, payload is `blake3(compressed_pubkey)[0..20]` (20-byte key hash), HRP by network.
- Genesis message/string is network-configurable (`genesis_message`), so new networks can be generated from config.
- Smart contracts: not included.

## 2) Important Notes and Tradeoffs

- Schnorr is a good default if we use a mature library (`secp256k1`) and strict message/domain separation.
- Fixed subsidy means perpetual emission (inflation never goes to zero). Difficulty does not set price directly; market demand does.
- "Leading zeros" and "hash <= target" are equivalent views; this project uses explicit numeric target comparison only.
- BLAKE3 256-bit hash can also be visualized as a 16x16 bitmap (256 bits), optional utility.

## 3) Repo Structure TODO

- [x] Create Cargo workspace members:
- [x] `crates/core` (types, serialization, hash wrappers).
- [x] `crates/consensus` (tx/block validation, PoW, retarget).
- [x] `crates/storage` (DB adapters and chainstate).
- [x] `crates/mempool` (tx pool, conflict handling).
- [x] `crates/p2p` (protocol, peers, sync).
- [x] `crates/node` (orchestrator, startup, config).
- [x] `crates/miner` (template builder, nonce loop).
- [x] `crates/wallet` (mnemonic, HD keys, sign/send).
- [x] `crates/rpc` (CLI/RPC surface).
- [x] Keep `src/main.rs` as thin bootstrap only.

## 4) Configuration TODO

- [x] Add `config/chain.toml`:
- [x] `network_id`
- [x] `target_block_time_sec = 120`
- [x] `difficulty_adjustment_window = 20`
- [x] `difficulty_clamp_up` and `difficulty_clamp_down`
- [x] `max_block_weight` or `max_block_size`
- [x] `max_tx_size`
- [x] `max_mempool_txs`
- [x] `coinbase_maturity`
- [x] `block_subsidy`
- [x] `hrp` for addresses
- [x] `genesis_*` fields
- [x] `genesis_message` (human-readable string embedded in genesis coinbase/script)
- [x] Add separate presets: `devnet.toml`, `testnet.toml`, `mainnet.toml`.

## 5) Cryptography TODO

- [x] Add hash API:
- [x] `hash256(data) -> [u8; 32]` using BLAKE3.
- [x] Define canonical transaction and block serialization for hashing.
- [x] Integrate secp256k1 Schnorr signing and verification.
- [x] Enforce canonical signatures and strict pubkey parsing.
- [x] Implement compressed pubkey encode/decode (SEC33).
- [x] Add domain-separated signing tags for tx signing digest (`SCAM-tx-signing-v1`).

## 6) Wallet and Key Management TODO

- [ ] Implement BIP39 mnemonic generation (12/24 words).
- [x] Implement wallet restore from mnemonic.
- [ ] Implement BIP32 HD derivation.
- [ ] Freeze derivation path in config/constants.
- [ ] Derive compressed pubkeys for address generation.
- [ ] Derive address payload from `blake3(pubkey_compressed)[0..20]`.
- [ ] Add encrypted at-rest key storage.
- [ ] Add wallet rescan (rebuild UTXO ownership from chain).

## 7) Address and QR TODO

- [x] Implement Bech32m address encode/decode with network HRP.
- [x] Implement payment URI: `coin:<address>?amount=<n>&label=<text>`.
- [x] Implement QR generation for payment URI (PNG + terminal ASCII optional).
- [x] Add CLI:
- [x] `wallet address`
- [x] `wallet address --qr`
- [x] `wallet decode <address>`

## 8) Transaction Model TODO (UTXO)

- [x] Define tx structures:
- [x] `TxIn { prev_out, signature, pubkey_compressed, sequence }`
- [x] `TxOut { value, key_hash20 }`
- [x] Define `txid = hash256(serialized_tx_without_witness_mutable_fields)` (freeze exact rule).
- [x] Validate:
- [x] inputs exist in UTXO
- [x] signatures valid
- [x] `sum(inputs) >= sum(outputs)`
- [x] no overflow / no negative amounts
- [x] coinbase special rules enforced
- [ ] Fee policy:
- [x] min relay fee
- [x] mempool sorting by fee rate

## 9) Mempool TODO (Conflict Rule)

- [x] Keep index `spent_outpoint -> txid`.
- [x] On incoming tx:
- [x] if no conflict, validate then insert.
- [x] if conflict exists, compare numeric `new_txid` vs `old_txid`.
- [x] if `new_txid < old_txid`, replace old tx and evict descendants.
- [x] else reject new tx.
- [ ] Broadcast replacement/eviction events to peers as inventory updates.
- [ ] Add orphan tx pool with size/time limits.
- [ ] Add eviction policy for full mempool.

## 10) Block and Chain TODO

- [x] Define block header:
- [x] `version, prev_hash, merkle_root, timestamp, target, nonce`.
- [x] Compute and validate merkle root.
- [x] Validate PoW with numeric target compare (`hash <= target`).
- [x] Validate block tx ordering and coinbase position.
- [x] Validate subsidy + fees in coinbase output total.
- [x] Implement chain selection by cumulative work (not height only).
- [x] Implement reorg: disconnect old branch, connect new branch.

## 11) Difficulty Retarget TODO

- [x] Every `N=20` blocks recompute target:
- [x] `expected = N * target_block_time_sec`
- [x] `actual = time(last) - time(last-N)`
- [x] `new_target = old_target * actual / expected`
- [x] Clamp change per window (for stability).
- [x] Enforce min/max target bounds.
- [x] Add protections for timestamp abuse:
- [x] median-time-past check
- [x] max future block time

## 12) Storage TODO

- [x] Pick DB engine (`redb` embedded backend added in `scam-storage`).
- [ ] Buckets/tables:
- [ ] blocks by hash
- [ ] headers by hash
- [ ] block index (height, work, parent)
- [x] UTXO set
- [x] chain tip metadata
- [ ] mempool persistence (optional, bounded)
- [ ] peer address book
- [ ] Atomic commit for block connect/disconnect state updates.
- [ ] Recovery and reindex mode.

## 13) P2P TODO (Reliable Minimal Gossip)

- [x] Define protocol messages:
- [x] `version`, `verack`
- [x] `ping`, `pong`
- [x] `inv`, `getdata`, `tx`, `block`
- [x] `getheaders`, `headers`
- [ ] `getblocks` (optional if headers-first + getdata is enough)
- [x] Use inventory-first propagation:
- [x] announce hashes via `inv`
- [x] request unknown objects via `getdata`
- [x] send full object only on request
- [x] Maintain per-peer `known_inventory` to avoid duplicate sends.
- [x] Keep local dedup cache for recently seen object IDs.
- [x] Implement headers-first sync for new nodes.
- [x] Implement peer scoring and ban for invalid data spam.
- [x] Add rate limits and max message size guards.

## 14) Mining TODO

- [x] Build block template from mempool by fee rate.
- [x] Insert coinbase with fixed subsidy + collected fees.
- [x] Implement nonce search loop.
- [x] Add extra nonce in coinbase to extend search space.
- [ ] Rebuild template on new best block or mempool updates.
- [x] Add CPU miner mode for devnet/testnet.

## 15) Node and RPC TODO

- [x] Node CLI:
- [x] `node run --network <devnet|testnet|mainnet>`
- [x] `node status`
- [x] `node add-peer <addr>`
- [x] `node get-block <hash>`
- [x] `node get-tx <txid>`
- [x] Wallet CLI:
- [x] `wallet new`
- [x] `wallet restore`
- [x] `wallet balance`
- [x] `wallet send`
- [x] `wallet address --qr`
- [x] Add JSON-RPC or REST facade for automation. (`scam-node rpc-serve` supports `/health`, `/status`, `/block/<height>`, `/tx/<height>/<index>`)

## 16) Test Plan TODO

- [ ] Unit tests:
- [ ] hash determinism and serialization compatibility
- [ ] signature verification and pubkey parsing
- [ ] merkle root generation
- [ ] target math and retarget formula
- [ ] mempool replacement by lower txid rule
- [ ] Integration tests:
- [ ] 3+ node tx propagation via inv/getdata
- [ ] block propagation and dedup behavior
- [ ] initial sync from genesis to tip
- [ ] fork + reorg correctness
- [ ] difficulty update every 20 blocks
- [ ] wallet mnemonic restore and deterministic addresses
- [ ] Soak test:
- [ ] local devnet running for 24h with mining and tx flow

## 17) Launch Strategy TODO

- [ ] Phase 1: single-node consensus correctness (no P2P).
- [ ] Phase 2: mempool + mining + persistent chainstate.
- [ ] Phase 3: P2P gossip and headers-first sync.
- [ ] Phase 4: wallet, mnemonic, QR, send/receive UX.
- [ ] Phase 5: hardening, tests, docs, public testnet.
- [ ] Phase 6: mainnet parameter freeze and genesis lock-in.

## 18) Open Constants to Revisit Later

- [ ] `coinbase_maturity` (suggest `100`).
- [ ] `min_relay_fee` baseline.
- [ ] `max_block_size`.
- [ ] retarget clamp factors.
- [ ] mempool max size and orphan limits.

## 19) Optional Utility: 16x16 Hash Visualizer

- [x] Input: 32-byte hash.
- [x] Convert bytes to 256 bits (MSB-first, freeze exact bit order in code docs).
- [x] Render 16x16 matrix where `1 = white`, `0 = black`.
- [x] Provide CLI command: `scam-node hash-visual --hash-hex <hex>`.
