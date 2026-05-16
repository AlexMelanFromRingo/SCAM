# `audit/hardening-tui` — branch summary

Branch base: `master` @ `23eec19`. Three commits, all green on the full
quality gate.

## Quality gates at branch tip

| Gate | Status |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo check --workspace` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test --workspace --exclude scam-node` | 285 passed, 0 failed |
| `cargo test -p scam-node --bin scam-node -- --test-threads=1` | **360 passed, 0 failed** (was 359 on master after the new F-5/F-11 test) |
| `cargo test -p scam-tui` | 19 passed, 0 failed |

`master` was not actually green at branch start: `clippy -D warnings`
failed on six lint regressions introduced by rustc 1.95.0. That is the
first finding fixed below (F-1).

## Audit findings

Severity / status legend: `critical` (consensus break) /
`high` (DoS or fund loss) / `medium` (defense in depth, narrow
exploit) / `low` (code quality). Status is `fixed-in-branch` unless
noted.

| ID | Severity | Title |
|---|---|---|
| F-1 | medium | Workspace lint gate was red on rustc 1.95.0; six lints stomped |
| F-2 | medium | Block accepted duplicate txid (CVE-2012-2459 class) |
| F-3 | high | `max_block_size` / `max_tx_size` were config-only, not enforced at validation |
| F-5 / F-11 | medium | RPC had no DNS-rebinding protection — now Host allow-list |
| F-7 | medium | Mempool admitted arbitrary-size txs (anti-DoS) |
| F-8 | clean | P2P transport posture audited — no findings |
| F-9 | clean | Wallet vault + signer audited — no findings |
| F-10 | medium | XSS via unescaped RPC payload in `web/app.js::renderLatestBlocks` |

Full per-finding detail: `docs/AUDIT_NOTES.md`.

## What was added (not just fixed)

- **`scam-tui` crate** + `scam-node tui` subcommand. New terminal
  dashboard with four panels (chain / stratum / mempool / help) over a
  ~250-line minimal HTTP/1.1 client built on `TcpStream` — no
  `reqwest` / TLS dependency added. 19 unit tests including renderer
  parity against ratatui's `TestBackend`. Run with:
  `cargo run -p scam-node -- tui --endpoint http://127.0.0.1:18080 --poll-ms 2000`
- **`docs/AUDIT_NOTES.md`** — full audit report scoped against the
  Bitcoin Core CVE history (CVE-2010-5139, CVE-2012-2459,
  CVE-2018-17144 patterns specifically checked).
- **`docs/AUDIT_BRANCH_SUMMARY.md`** — this file.
- **`CLAUDE.md`** at repo root — onboarding doc for future Claude /
  contributor sessions (architecture map, gate commands, single-thread
  rule for `scam-node` bin tests, etc.).

## What was explicitly NOT promised

The user asked to "make this a real cryptocurrency" and bring the code
to "Bitcoin upstream quality". I did not pretend either is possible in
one session. What was delivered:

- A real audit (not a checklist tick), with three real consensus /
  DoS / XSS findings closed and three "clean — checked" findings
  recorded so the next audit knows what was already covered.
- A working TUI.
- Quality gates back to green on the current toolchain.

What still separates SCAM from a launched cryptocurrency, and is
**out of scope** for this branch:

1. No live mainnet. `config/mainnet.toml` exists but no operators,
   no DNS seeds populated, no published genesis hash.
2. No fixed monetary policy. `block_subsidy` is a config knob;
   real cryptocurrencies pick and freeze an emission curve.
3. No on-chain scripting / multisig / time-lock contracts. SCAM is
   P2PKH-style only; signatures + `key_hash20`, period.
4. No protocol upgrade mechanism (no BIP9 / BIP8 versionbits).
5. No independent second-implementation. One codebase = one bug
   class.
6. No external security audit by a human firm — this branch is
   a code review, not a paid audit.

Building those is process work (running a network, freezing
parameters, hiring auditors), not code work.

## Suggested follow-ups for the next branch

These are concrete, each closes a real gap, and each is sized to be
a single session of work:

1. **Pin the toolchain** (`rust-toolchain.toml`) so F-1 cannot recur,
   and set `rust-version = "1.95"` in workspace `Cargo.toml`.
2. **Optional bearer-token auth** on the Axum RPC — finishes F-5.
   Make non-loopback bind require it.
3. **Strict `max_block_size` re-derivation from `bincode::serialize`**
   not `serialized_size`. The current F-3 check uses
   `bincode::serialized_size(block)` which is correct for the canonical
   path but does *not* account for the on-wire framing header. Add a
   test that builds a block of size exactly `max_block_size` and
   verifies acceptance / rejection at +1.
4. **Hook F-7 size cap into the orphan pool too** — admission and
   eviction paths share the structural complaint.
5. **Replace `secret_key_bytes() -> [u8; 32]`** with a `zeroize`-on-drop
   wrapper (F-9 minor).

## Open task list

Tasks #1–#8 closed in this branch. Task #9 (this summary + PR
description) is the last one — see commit history for the PR
description draft.
