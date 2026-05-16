# SCAM Protocol Design Notes (`audit/hardening-tui`)

Scope: design decisions for the work landing in this branch — monetary
policy, soft-fork mechanism (versionbits), absolute/relative timelocks,
and multisig outputs. Each decision is cross-checked against the existing
SCAM philosophy and the relevant Bitcoin BIP / Monero source.

## Philosophy bullets (extracted from current `master`)

- **Cryptography**: BLAKE3 PoW, BIP340 Schnorr signatures, bech32m
  addresses. Hash-flavored where Bitcoin uses SHA-256, no SHA-1.
- **No segwit**: single tx format, signatures live inside the txid.
  Deterministic signing (`sign_schnorr_no_aux_rand`) closes
  third-party malleability.
- **Strict arithmetic**: `u128` accumulators on amounts, `checked_add`
  everywhere on fee math.
- **Config-first**: every chain parameter is in `ChainConfig` and
  validated on load. Genesis is reproducibly derived from config.
- **Domain-separated sighash**: `network_id` mixes into every signing
  digest. Cross-network replay is already closed (test
  `signature_replay_across_chain_domains_is_rejected`).
- **Per-output spend authorization is just `RIPEMD160(BLAKE3(pubkey))`**:
  P2PKH-equivalent. No on-chain script VM today.
- **Already in the type**: `tx.lock_time: u32`, `TxIn.sequence: u32`.
  `tx_is_final_for_block` already implements the BIP68-flavored
  height-vs-time-threshold split at `500_000_000` and the
  `sequence == u32::MAX` "final" bypass.

## 1. Monetary policy — halving + optional tail emission

### Reference

- Bitcoin: halve `block_subsidy` every 210_000 blocks (~4 years at 10
  min/block). Hard cap = 21M coins because halvings eventually round
  down to 0.
- Monero: emission decays smoothly then floors at **~0.6 XMR per
  2-minute block** ("tail emission"), so miner subsidy never reaches
  zero. Rationale: avoid the "fee-only chain must be perfectly secure"
  bet Bitcoin makes; price out at <1% annual inflation that trends to 0
  as supply grows.

### Decision

SCAM gets **both knobs, both config-driven, both halving-style**:

```toml
block_subsidy            = 50          # initial (already exists)
halving_interval_blocks  = 210_000     # NEW: halve every N blocks
tail_emission            = 1           # NEW: floor; 0 disables
```

Subsidy at height `h`:

```rust
fn compute_block_subsidy(h: u64, cfg: &ChainConfig) -> u64 {
    let Some(interval) = NonZeroU64::new(cfg.halving_interval_blocks) else {
        return cfg.block_subsidy;          // halvings disabled
    };
    let halvings = h / interval.get();
    if halvings >= 64 {                    // u64 shifts max
        return cfg.tail_emission;
    }
    let halved = cfg.block_subsidy >> halvings;
    halved.max(cfg.tail_emission)
}
```

### Why this shape

- **Backwards-compatible default**: when `halving_interval_blocks = 0`
  the old behavior (fixed subsidy forever) is preserved. Existing
  devnet/testnet configs need no change to keep working.
- **Tail floor solves Monero's incentive concern** without committing
  to a hard cap.
- **`>>` on u64 is overflow-safe and cheap** — at h≈1.3e19 (u64::MAX),
  halvings = 6e13 / 210_000 ≈ 6.2e8 — fits in u64; the 64-shift
  guard above handles the corner.
- **One pure function**, easily called from `validate_and_apply_block_with_limits`
  in place of today's hardcoded `block_subsidy` argument.

### Migration

Existing `ChainConfig::block_subsidy` stays. New fields default to 0
(= disabled). `validate_and_apply_block` keeps its constant-subsidy
signature; chain runtime switches to a new wrapper that passes the
computed per-height subsidy.

---

## 2. Soft-fork mechanism — BIP9 versionbits, condensed

### Reference (BIP9 verbatim)

- 5 states: `DEFINED` → `STARTED` → `LOCKED_IN` → `ACTIVE`, or
  any-from-STARTED → `FAILED`.
- Evaluated at retarget boundaries (Bitcoin: every 2016 blocks).
- `STARTED → LOCKED_IN` when ≥ threshold blocks in the prior window
  signaled the deployment bit.
- Clock: median time of past 11 blocks (`MTP`).
- Version field high bits = `0b001`; bits 0..28 = deployment bit slots.

### Decision

SCAM gets the same machine, parameterized by the chain config so any
fork that uses `config-scaffold` can tune the cadence.

```toml
# ChainConfig additions
versionbits_window_blocks = 2016        # retarget cadence for vbits
versionbits_threshold     = 1916        # 95% of window

[[deployments]]
name        = "csv"                     # relative locktime via sequence
bit         = 0
start_unix  = 1_770_768_000
timeout_unix= 1_802_304_000             # 1 year window
```

`DeploymentState` is computed from the most-recent retarget boundary on
the active chain. `is_active(name, height)` is a cheap lookup once the
state for the enclosing window is cached.

Deployment bit signaling: `(header.version >> bit) & 1 == 1` AND
`(header.version & 0xE000_0000) == 0x2000_0000`.

### Why this shape

- **No chain-id collision**: SCAM headers already carry `version: u32`.
  We just enforce the magic-prefix rule on signaled headers, which is
  forwards-compatible (today every miner sets `version = 1` so no
  current header collides with the magic-prefix range).
- **Cadence parameterized**: Bitcoin's 2016-block / two-week assumption
  is too long for SCAM's 2-minute block. Devnet keeps the existing
  20-block difficulty window; mainnet picks its own.
- **No live deployments shipped yet** — the infrastructure ships
  empty. First real deployment will activate CSV/multisig in a future
  branch with proper signaling and testnet rehearsal.

---

## 3. Time-locks — what already exists, what to add

### Status quo (`crates/consensus/src/utxo.rs::tx_is_final_for_block`)

```rust
if tx.lock_time == 0 { return true; }
if tx.inputs.iter().all(|i| i.sequence == u32::MAX) { return true; }
if tx.lock_time < 500_000_000 {
    (tx.lock_time as u64) <= block_height
} else {
    (tx.lock_time as u64) <= block_time
}
```

This is structurally **BIP65-equivalent at the transaction level** —
the threshold split, the sequence-final bypass, and the comparison
operator all match.

What's *missing* relative to Bitcoin's mature time-lock suite:

- **Per-input relative locks (BIP68/CSV)**: spend can require N blocks
  or N seconds to have elapsed since the input's UTXO was created.
- **Per-output absolute locks (BIP65/CLTV via script)**: SCAM has no
  script, so this only matters if we add a new output type that
  carries an explicit `spend_after_height` field.

### Decision

- Ship a clarifying refactor + test pass on the existing
  `tx_is_final_for_block` (no behavior change). Names the
  `LOCKTIME_THRESHOLD` constant publicly and adds doc cross-refs to
  BIP65.
- **Defer per-input CSV and per-output explicit CLTV** to a follow-up
  branch, gated on a versionbits deployment. The infrastructure
  shipped here makes that follow-up clean.

This keeps "single tx format" and unbreaks no existing test.

---

## 4.5. MuSig2 — considered, deliberately deferred

### Why it would be valuable

- Single 64-byte aggregated Schnorr signature on chain, regardless of
  N participants. Indistinguishable from a plain P2PKH spend.
- Cheaper verification (one Schnorr verify, not k).
- Privacy: on-chain analysis cannot tell a multisig spend from a
  single-key spend.
- Aligns with SCAM's "single tx format, no script" philosophy: MuSig2
  is the way to do multisig without needing on-chain scripts.

### Why this branch does NOT ship it

1. **No stable crates.io secp256k1 supports MuSig2.** The reference
   implementation lives in `secp256k1-zkp` (a git-only library
   tracking the upstream `libsecp256k1` PR series for BIP327). Pulling
   a git dep ties SCAM's reproducible build to a specific commit on
   an upstream branch that may rebase. We refuse to make the
   workspace's reproducibility depend on a third-party git history.

2. **Re-implementing BIP327 from scratch is dangerous.** MuSig2's
   nonce-aggregation step is exactly the surface that Wagner's
   k-list attack targeted on MuSig1. BIP327 specifies countermeasures
   (binding factor `b`, nonce coefficient derivation, blame-checking
   on signing-session abort) that *must* be implemented exactly to
   the spec or the whole scheme is broken — silently, in a way
   normal unit tests do NOT catch. Production-grade MuSig2
   implementations have all had multiple iterations of cryptography
   review. We don't have that here.

3. **No silver-bullet alternative.** Older Schnorr aggregation
   schemes (MuSig1, BN-style) have known attacks. FROST is
   threshold-signature flavor with comparable complexity. None of
   them are "MuSig2 minus the hard parts".

### Conditions under which this branch's call would change

Any one of:

- `secp256k1-zkp` ships a tagged crates.io release with MuSig2 in
  a stable namespace.
- A second independent codebase audits SCAM's would-be MuSig2
  implementation (and pays for the review).
- The chain successfully runs without aggregated multisig for long
  enough that the on-chain footprint becomes a real bottleneck
  worth the risk delta.

### What ships instead

- **Naïve k-of-n** at consensus level (`crates/consensus/src/multisig.rs`,
  shipped in this branch). On chain a spend carries k * 64 bytes of
  Schnorr signatures, one per participating key, plus the descriptor
  blob. Larger on chain than MuSig2; same security model on the
  Schnorr-verify primitive.
- **PartialMultisigTx (PSBT-lite)** in `crates/wallet/src/psbt.rs`
  for off-chain coordination, also this branch. Forward-compatible:
  the JSON envelope is versioned, so a future MuSig2 deployment
  ships as `version: 2` and v1 wallets cleanly refuse the new format.

---

## 4. Multisig — design note only, full implementation deferred

### Two viable shapes

1. **New output spend type** (`SpendCondition::MultiSig { script_hash20 }`)
   — clean, but breaks `TxOut` serialization and every test that
   builds a TxOut by struct literal. Hard fork from any live chain.
2. **Reuse `key_hash20` as a discriminated tag** — first byte selects
   the spend type. Stays in the existing 20-byte slot but loses 8 bits
   of address entropy. Not a hard fork on the wire.

### Decision (in this branch)

Implementation deferred. Two reasons:

1. The wallet, address-display, send-preview, and CLI surfaces all
   assume a single output type. Every one needs a multisig-aware
   variant. That is a multi-day branch on its own.
2. Multisig benefits most when combined with CSV (timelock multisig)
   and BIP340 Schnorr key aggregation (MuSig2). Doing them together
   keeps the address format stable; doing them piecemeal forces two
   address-format bumps.

What ships here: the versionbits infrastructure that the multisig
deployment will use, and a `MULTISIG_MVP.md` follow-up doc capturing
exact next-step work.

---

## Roll-out plan (post-merge of this branch)

1. **Followup-A** (separately reviewable):
   - CSV per-input relative locktime, gated on versionbits `bit=0`.
   - Threshold-deployment test on synthetic devnet.
2. **Followup-B**:
   - `SpendCondition` enum + `MultiSig` variant.
   - Wallet support (address derive, sign with k keys, balance
     reporter that understands multisig).
   - MuSig2-style key aggregation if upstream `secp256k1-zkp` becomes
     available without git deps.
3. **Followup-C**:
   - Mine a real mainnet genesis nonce. Freeze + publish hash.
   - Operator runbook for first-three-nodes bootstrap, DNS seeds.

The work in this branch unblocks all three.
