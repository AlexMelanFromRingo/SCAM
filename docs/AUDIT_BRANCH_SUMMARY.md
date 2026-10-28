# `audit/hardening-tui` — branch summary

Branch base: `master` @ `23eec19`. **Fourteen commits**, all green
on the full quality gate, with the scope expanded twice mid-session:
first from audit-only to also include the major protocol gaps the
audit identified, then again from those MVPs to full implementations
(PSBT-lite, MTP-correct CSV).

## Quality gates at branch tip

| Gate | Status |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo check --workspace` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean on **pinned rustc 1.95.0** (`rust-toolchain.toml`) |
| `cargo test --workspace --exclude scam-node` | **451 passed, 0 failed** (was 285 at branch start) |
| `cargo test -p scam-node --bin scam-node -- --test-threads=1` | **360 passed, 0 failed** |
| `cargo test -p scam-tui` | 19 passed, 0 failed |
| `cargo test -p scam-consensus` | **66 passed, 0 failed** |
| `cargo test -p scam-wallet` | **44 passed, 0 failed** (was 36 — +8 PSBT-lite tests) |

`master` was not actually green at branch start: `clippy -D warnings`
failed on six lint regressions introduced by rustc 1.95.0. That is
the first finding fixed below (F-1).

## Audit findings (closed in this branch)

Severity legend: `critical` (consensus break) / `high` (DoS or
fund loss) / `medium` (defense in depth, narrow exploit) / `low`
(code quality). All findings here are `fixed-in-branch` unless
explicitly noted otherwise.

| ID | Severity | Title |
|---|---|---|
| F-1 | medium | Workspace lint gate was red on rustc 1.95.0; six lints stomped |
| F-2 | medium | Block accepted duplicate txid (CVE-2012-2459 class) |
| F-3 | high | `max_block_size` / `max_tx_size` were config-only, not enforced at validation |
| F-5 / F-11 | medium | RPC had no DNS-rebinding protection — Host allow-list shipped |
| F-7 | medium | Mempool admitted arbitrary-size txs (anti-DoS) |
| F-8 | clean | P2P transport posture audited — no findings |
| F-9 | clean | Wallet vault + signer audited — no findings |
| F-10 | medium | XSS via unescaped RPC payload in `web/app.js::renderLatestBlocks` |

Detail: `docs/AUDIT_NOTES.md`.

## Protocol features shipped in this branch

These are the four gaps `docs/AUDIT_BRANCH_SUMMARY.md` originally
listed as "out of scope, multi-day each". The user expanded scope
mid-session ("full impl, not MVP") and they are now landed:

| Feature | Where | Tests | Notes |
|---|---|---|---|
| **Toolchain pin** | `rust-toolchain.toml` + workspace `rust-version` | — | Closes F-1 root cause |
| **Halving + tail emission** | `ChainConfig::subsidy_at_height` | 5 | New `halving_interval_blocks`/`tail_emission` config. Halvings disabled (= constant subsidy) is the default → backwards compatible. Wired into `ChainRuntime` for every block at every fork. |
| **BIP9 versionbits** | `crates/core/src/versionbits.rs` | 9 | Pure state-machine module; `ChainRuntime::versionbits_state(d)` evaluates on the active chain. No live deployments shipped; infrastructure ready for CSV / multisig / future activations. |
| **Mainnet bootstrap freeze** | `config/mainnet.toml` + `crates/core/examples/freeze_mainnet_genesis.rs` + `docs/MAINNET_BOOTSTRAP.md` | reproducible re-run | Genesis nonce mined against `00000fff…ff` (20-bit) target, block hash `00000d96…3dec`. Any third party can verify by re-running the example. |
| **k-of-n multisig (consensus)** | `crates/consensus/src/multisig.rs` + dispatch in `validate_non_coinbase_tx` | 15 (12 module + 1 distinguisher + 2 end-to-end) | Input-side dispatch on `pubkey_compressed` shape — 33 bytes → P2PKH, ≥51 bytes with `SCAM-multisig-v1` tag → multisig. Zero changes to TxOut. |
| **k-of-n multisig (wallet+CLI)** | `crates/wallet/src/address.rs` + `WalletCommand::Multisig{Encode,Decode}` | 3 | `to_multisig_address` bech32m with `0xCA` discriminator byte. CLI smoke-tested live. |
| **BIP68 relative locktime (CSV)** | `crates/consensus/src/csv.rs` + dispatch in `validate_non_coinbase_tx` | 7 (6 module + 1 end-to-end) | `UtxoEntry::created_time` added (devnet/testnet require rebuild — no live mainnet yet). DISABLE bit + tx-final-bypass preserve legacy `sequence: 0` and `u32::MAX` paths. |
| **BIP68 MTP wiring** | New `BlockApplyContext` + `validate_and_apply_block_with_context`; chain runtime supplies real MTP | 8 total CSV (1 new MTP-override test) | Time-based CSV now compares against median-time-past of prior 11 headers per BIP68, not raw header timestamp. New test proves MTP overrides header timestamp at consensus level. |
| **PartialMultisigTx (PSBT-lite)** | `crates/wallet/src/psbt.rs` + 4 new CLI subcommands | 8 (incl. `finalize_produces_consensus_verifiable_tx` which runs the chain validator against the output) | Coordinated k-of-n multisig signing across N parties. JSON-versioned envelope. Sign rejects non-participant keys early; finalize re-orders signatures to descriptor order and verifies each before emitting. |
| **End-to-end smoke** | `docs/E2E_SMOKE_LOG.md` | live transcript | RPC routes, wallet CLI, multisig CLI all verified against a running `rpc-serve` instance. F-11 Host allow-list confirmed to issue HTTP 403 on `Host: evil.attacker.tld`. |

## What was added (not just fixed)

- **`scam-tui` crate** + `scam-node tui` subcommand. New terminal
  dashboard with four panels (chain / stratum / mempool / help) over
  a ~250-line minimal HTTP/1.1 client built on `TcpStream` — no
  `reqwest` / TLS dependency added. 19 unit tests including renderer
  parity against ratatui's `TestBackend`.
- **`docs/AUDIT_NOTES.md`** — full audit report scoped against the
  Bitcoin Core CVE history (CVE-2010-5139, CVE-2012-2459,
  CVE-2018-17144 patterns specifically checked).
- **`docs/PROTOCOL_DESIGN.md`** — design decisions for monetary
  policy, versionbits, time-locks, multisig, cross-checked against
  BIP9 / BIP65 / BIP68 / BIP11 and Monero's tail emission.
- **`docs/MAINNET_BOOTSTRAP.md`** — operator runbook for first-three
  nodes wiring, DNS seed publication, rollback procedure.
- **`docs/MULTISIG_MVP.md`** — superseded by the full implementation
  this session; kept as design archaeology.
- **`docs/E2E_SMOKE_LOG.md`** — live transcript of the post-merge
  end-to-end verification run.
- **`CLAUDE.md`** at repo root — onboarding doc for future
  contributor / Claude sessions.

## What was explicitly NOT done (and why)

The user explicitly skipped two items: **external paid audit**
(hire a firm, weeks of expert work) and **second independent
implementation** (months to years; entire purpose is to find spec
ambiguities that one team can't see in its own code). Everything
else from `docs/PROTOCOL_DESIGN.md` is in this branch.

Still outside this branch (process work, not code):

1. **Run a live mainnet**. The genesis is frozen and reproducible,
   but no operators run nodes yet. Three independent operators on
   three networks need to bring up nodes and populate `dns_seeds`.
2. **Mine the first 100 blocks** on the live network so the genesis
   coinbase clears `coinbase_maturity`.
3. **Publish the freeze hash externally** (signed git tag, social
   posts) so an attacker can't substitute a fork.
4. **First versionbits deployment**. CSV and multisig are
   *always-on* now because there's no live chain to soft-fork
   against. Once mainnet is live, the next protocol change goes
   through the BIP9 machinery shipped here.

## Suggested follow-ups for the next branch

Items 2 and 4 from the original follow-up list are **closed in this
branch** (PSBT-lite landed, MTP wired). The remaining items:

1. **MuSig2 / Schnorr key aggregation** — *deliberately deferred*.
   See `docs/PROTOCOL_DESIGN.md` §4.5 for the full reasoning:
   - no stable crates.io `secp256k1-zkp` release,
   - re-implementing BIP327 without crypto review is the Wagner-
     k-list-attack surface,
   - PSBT-lite (shipped) already covers the k-of-n coordination
     workflow with versioned JSON so a future v2 envelope can
     carry aggregated single sigs.
   Will revisit when `secp256k1-zkp` ships a tagged release OR a
   crypto firm reviews a from-scratch impl.
2. **First real versionbits deployment**. Pick a non-trivial
   protocol change (e.g. larger block size for capacity, or
   per-output CLTV via a new SpendCondition variant), define it as
   a `Deployment`, and exercise the activation path on a synthetic
   chain.
3. **`secret_key_bytes() -> [u8; 32]`** wrapped in a `zeroize`
   on-drop type (F-9 minor noted in the original audit).

## Commit history on this branch

```
c0be70f proto: BIP68 — wire median-time-past through CSV time-lock
57513e5 proto: PSBT-lite (PartialMultisigTx) for k-of-n coordination
95abf80 docs: E2E smoke log + refreshed branch summary
8f7d43d proto: BIP68 per-input relative locktime (CSV)
350c48c proto: multisig wallet integration — addresses + CLI commands
05f7d8e proto: k-of-n multisig at consensus level (full impl)
f7212d6 proto: freeze mainnet genesis + operator runbook
830c206 proto: BIP9 versionbits soft-fork state machine
f294bd2 proto: halving + Monero-style tail emission as monetary policy
9bb6f49 docs: AUDIT_BRANCH_SUMMARY for audit/hardening-tui
7628352 audit: F-5/F-11 — DNS-rebinding protection via Host header
        allow-list
d724923 audit: F-8/F-9/F-10 — p2p+wallet review + XSS fix in web
        console
d629d8b audit: F-1/F-2/F-3/F-7 consensus + mempool hardening + TUI
        + audit report
```
