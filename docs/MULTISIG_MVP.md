# Multisig MVP — Follow-up Branch Plan

Status: **not implemented in `audit/hardening-tui`**. The full design
is in `docs/PROTOCOL_DESIGN.md` §4; this document is the concrete
work-breakdown to implement it on a follow-up branch.

The scope was deferred (not skipped) for two reasons that are real and
not about laziness:

1. The wallet, address-encode/decode, send-preview, RPC handlers, web
   console, and **87 TxOut struct-literal call sites** all assume a
   single output type. Every one needs an enum-aware variant.
2. Multisig benefits most when shipped together with BIP340 Schnorr
   key aggregation (MuSig2) and CSV per-input relative timelocks
   (timelock multisig). Two disjoint follow-ups would force two
   address-format bumps. One bigger branch is cleaner.

## Target shape

```rust
// crates/core/src/types.rs
pub enum SpendCondition {
    P2pkh { key_hash20: [u8; 20] },
    MultiSig { script_hash20: [u8; 20] },
}

pub struct TxOut {
    pub value: u64,
    pub spend: SpendCondition,
}
```

`script_hash20 = RIPEMD160(BLAKE3(tag || k || n || pubkey_1 || ... || pubkey_n))`
where `tag = b"SCAM-multisig-v1"`.

`TxIn` is *unchanged* on the wire. On the spend side, multisig inputs
provide:

- `signature` — `k` Schnorr signatures concatenated (each 64 bytes).
- `pubkey_compressed` — the full N-pubkey list, serialized as
  `[u8; 33 * N]`, plus a 2-byte `(k, n)` header.

Validation:

1. Reconstruct `script_hash20` from the bytes in `pubkey_compressed`;
   verify equality with the UTXO's `script_hash20`.
2. Split `signature` into k 64-byte slices.
3. For each signature: verify against the signing digest using *some*
   pubkey from the set. Each pubkey may verify at most one signature.
   Reject if fewer than k distinct verifications succeed.

## Why bake it in from genesis (no soft-fork)

SCAM has no live mainnet. Multisig as a "new output type" is a
breaking change to the consensus rules, but on an unlaunched chain a
"breaking change" is just a rule. The versionbits machinery shipped
in this branch is for *post-launch* deployments; pre-launch we just
freeze the rules including multisig.

## Address encoding

`SpendCondition::MultiSig { script_hash20 }` gets a new bech32m HRP
suffix: today P2PKH uses `sd1...` (or per-config). Multisig uses
`sd1m...` — the first data character after the HRP `1` separator
disambiguates. The change is fully backwards-compatible with existing
P2PKH addresses (their first data character is not `m`).

## Wallet changes

- `wallet new-multisig --k 2 --pubkey <hex> --pubkey <hex> ...` →
  generates multisig descriptor + address.
- `wallet sign-multisig --psbt <file> --key <wif>` → adds one
  signature to a partially signed tx. PSBT-like format with just the
  pieces SCAM needs (no script).
- `wallet send` learns to recognize multisig outputs in balance scan.

## Test plan

1. Round-trip serialize/decode TxOut for both variants.
2. P2PKH spend path stays bit-identical (regression test from the
   existing valid_block_with_signed_spend_applies suite).
3. New multisig path: 2-of-3 valid, 1-of-3 invalid, 3-of-3 valid,
   duplicate-signature-on-one-pubkey invalid.
4. Address encode/decode round-trip for both variants.
5. PSBT-lite round-trip (sign → partial → combine).
6. Mempool admission for multisig spends.
7. Wallet rescan reports multisig balances.

## Estimated scope

- 1500-2500 LoC across `core`, `consensus`, `wallet`, `node`,
  `mempool`, `web`.
- 1-2 days of focused work, with the test plan above as the gate.
- No external dependencies needed beyond what SCAM already pulls in
  (secp256k1 already supports Schnorr).

## Follow-up that this unblocks

- **CSV (per-input relative timelock)** gated on a versionbits
  deployment. The deployment bit is `0` per `docs/PROTOCOL_DESIGN.md`
  §3.
- **Timelock multisig** = CSV + multisig combined into one
  spend-condition variant. Used in escrow / vault patterns.
