# SCAM Mainnet Bootstrap

This document is the operator runbook for starting the SCAM mainnet
chain from genesis. The genesis itself is frozen here; the social /
peer-discovery half (DNS seeds, first three nodes, exchange listings,
etc.) is process work that lives outside this branch.

## Frozen genesis (audit/hardening-tui)

| Field | Value |
|---|---|
| `genesis_message` | `SCAM mainnet bootstrap @ audit/hardening-tui 2026-05-16` |
| `genesis_timestamp` | `1778904904` (2026-05-16 UTC) |
| `genesis_target` | `00000fff…ff` (20-bit difficulty) |
| `genesis_nonce` | `689878` |
| `genesis_reward_key_hash20` | `00…00` (unspendable, by convention) |
| Resulting `block_hash` | `00000d962d678a42587e8c9a224eebefc4e4533c0e0f174aab02b9e9b5e33dec` |
| Resulting `merkle_root` | `42dab5726e701ab8a7a25853306a63db9ff375600452a7f92eebe8c3af23f038` |

These values are baked into `config/mainnet.toml`. To re-derive (sanity
check), run:

```bash
cargo run --release -p scam-core --example freeze_mainnet_genesis
```

The example reads the same `config/mainnet.toml`, overwrites the four
genesis fields to the frozen values listed above, and grinds nonces
until `block_meets_pow` passes. The same `(target, message, timestamp,
reward_key_hash20)` tuple always solves to the same nonce, so the
output is deterministic. If the printed nonce differs from `689878`,
the toml has drifted and the freeze is invalid.

## Why the genesis reward is unspendable

`genesis_reward_key_hash20 = 00…00` is conventional: it points to no
known pubkey, so the 50-coin reward in the genesis coinbase cannot be
spent. Bitcoin's genesis is also unspendable but for a different
reason (Satoshi inserted the coinbase tx outside the chain UTXO set
by accident). Here it's an explicit choice that prevents anyone — the
chain authors included — from owning the first 50 coins.

## Difficulty parameter sanity

The genesis target is `00000fff…ff`. That's roughly a 20-bit
proof-of-work, which corresponds to ~1M hash attempts on average. On
a single modern CPU the genesis grinds in ~1 second. This is
deliberately low so the bootstrap is reproducible from any developer
laptop; the live mainnet target adjusts upward via the `lwma`
difficulty algorithm (see `docs/PROTOCOL_DESIGN.md`).

For comparison: Bitcoin genesis was mined at `0x1d00ffff` (~32-bit
difficulty), which on 2009 CPUs took hours. We chose much easier
because:

1. Reproducibility matters more than "genesis cost" — a frozen,
   verifiable nonce is the contract.
2. Difficulty rises quickly once miners arrive; the genesis bar is
   noise compared to block 100.

## First-three-nodes bootstrap (process steps)

These are NOT in code; they are operator actions. Listed here so the
next person picking up the branch knows what's missing.

1. **Build a release binary** on three independent hosts:
   ```bash
   cargo build --release -p scam-node
   ```
2. **Verify each binary recomputes the same genesis hash**:
   ```bash
   ./target/release/scam-node status --network mainnet --config config/mainnet.toml
   ```
   Expect tip hash = `00000d962d678a42587e8c9a224eebefc4e4533c0e0f174aab02b9e9b5e33dec`.
3. **Open inbound P2P** on each host (default port `18444`).
4. **Manually wire the three nodes** (cross-add as peers) and verify
   handshake completes:
   ```bash
   ./target/release/scam-node add-peer --network mainnet --peer <host>:18444
   ./target/release/scam-node sync-peer --network mainnet --config config/mainnet.toml --peer <host>:18444
   ```
5. **Start `relay-serve`** on each host so they relay each other's
   announcements:
   ```bash
   ./target/release/scam-node relay-serve --network mainnet --config config/mainnet.toml --bind 0.0.0.0:18444
   ```
6. **Start `stratum-serve` + a miner** on at least one host. The
   first 100 blocks (`coinbase_maturity`) will be unspendable; this
   is the warm-up window. Once height = 100, the miner's coinbase
   from block 0 is spendable and the chain has its first
   transactable funds.
7. **Populate `dns_seeds` in `config/mainnet.toml`** with at least
   two hostnames whose A records resolve to long-lived peers. Push
   that config update to all operators. New nodes use those seeds
   for first connection.
8. **Publish the freeze hash** outside the repo so an attacker can't
   silently substitute a different chain. Suggested venues: a signed
   tag in this git repo, a tweet from a known maintainer, a
   commit-hash in any external mirror.

## What changes mainnet → mainnet "real"

Right now `config/mainnet.toml` is a frozen genesis but the chain has
no live operators. The difference between this file and an
operational cryptocurrency is *people*, not code:

- Multiple independent node operators on different network providers.
- Miner ecosystem with hash rate distribution.
- At least one block explorer + wallet other than the reference.
- An exchange willing to list the asset.
- A documented protocol-upgrade process (versionbits is already
  in place; see `docs/PROTOCOL_DESIGN.md` §2).

This branch handles the code; the rest is community work.

## Rollback / re-freeze procedure

If a critical bug is found before mainnet is "live" (anyone-can-mine
hasn't started), the freeze can be revoked by:

1. Reverting the `genesis_*` lines in `config/mainnet.toml` to the
   prior values (see `git log -p config/mainnet.toml`).
2. Updating `FROZEN_MESSAGE` and `FROZEN_TARGET_HEX` in
   `crates/core/examples/freeze_mainnet_genesis.rs`.
3. Re-running the example.
4. Updating this document.

Once mainnet is live (any third-party node has accepted blocks under
the current rules), the freeze is binding — re-freezing forks the
chain.
