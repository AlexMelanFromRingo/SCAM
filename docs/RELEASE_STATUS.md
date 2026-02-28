# SCAM Release Status

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
