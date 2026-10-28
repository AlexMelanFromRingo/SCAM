# SCAM Release Status

## 0.3.0 (`2026-10-28`)

State:
- Final release of the 0.3 line; supersedes `0.3.0-rc3`.
- Includes the 2026-10-27/28 production-readiness audit: every finding in
  `docs/PRODUCTION_AUDIT.md` is fixed or decided by the owner. Upgrading from
  rc3 needs fresh devnet/testnet data (see "Behaviour changes operators must
  know" there).
- Gates on the release commit:
  - `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`: clean
  - `cargo test --workspace --exclude scam-node`: 494 passed
  - `cargo test -p scam-node --bin scam-node -- --test-threads=1`: 348 passed; `--test cli_main`: 1 passed
  - `scripts/local-e2e-flow.sh`: `[e2e] success`
  - `scripts/sv2-conformance-matrix.sh` (CI): plain + noise_xx
- `docs/mainnet-freeze.lock.json` matches the code: genesis
  `00000d962d678a42587e8c9a224eebefc4e4533c0e0f174aab02b9e9b5e33dec`,
  `config/mainnet.toml` sha256 `d9dc7212…483f6d5e`.

Not run for this release:
- mutation stages 2/3 on the audited code (the last closure is RC1's),
- fuzzing campaigns,
- multi-hour soak / WAN profiles,
- external security audit.

## RC1 (`2026-02-28`)

State:
- `RC1` candidate.
- Core workspace gates are green:
  - `cargo fmt --all`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
- Mutation closure:
  - Stage 2 closure rerun: `0 missed`, `0 timeout`
  - Stage 3 full workspace rerun: `2358 tested`, `2064 caught`, `0 missed`, `0 timeout`, `294 unviable`

Deferred non-code gates:
- long-run soak profile acceptance,
- external security audit closure,
- full maximum-detail documentation pack finalization.
