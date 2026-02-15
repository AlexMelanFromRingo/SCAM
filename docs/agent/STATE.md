# Agent State (Recovery Notes)

Last updated: 2026-02-15

## Mutation status snapshot
- Stage1 (`scripts/mutation-staged.sh stage1`): `529 mutants tested in 3m: 471 caught, 58 unviable` (0 missed, 0 timeout).
- Stage2 focused set (node/p2p/stratum risky paths):
  - `81 mutants tested in 3m: 77 caught, 4 unviable`.
  - `90 mutants tested in 3m: 86 caught, 4 unviable`.
  - Focus includes: `decode_optional_hex32`, `max_requests_reached`, `map_sv2_read_result`, `update_sv2_conformance_state`, HTTP read/timeout/closed guards, `guess_content_type`, `run_command`, `run_wallet`, `run_sv2_conformance`, `run_stratum_serve`, p2p `send_message`.
- Full Stage2 (`scripts/mutation-staged.sh stage2`): previously interrupted by power outage; rerun still required from latest commit.
- Stage2 old-hotspot replay (after fixes):
  - `81 mutants tested in 4m: 77 caught, 4 unviable` (0 missed, 0 timeout).

## Recent commits relevant to recovery
- `e5c7548` - stratum payout wiring + watch-only balance by address + rpc runtime refresh + lab script updates.
- `8e95f74` - additional node mutation-killer tests (IO guard behavior, sv2 conformance error tracking, HTTP close/error paths, svg content-type, run_from_args dispatch, wallet balance-address HRP validation).
- `bbfc563` - mutation CI/script acceleration knobs (`shard`, `examine_re`, `exclude_re`, `iterate`) for targeted and split runs.

## Immediate next actions
1. Run full Stage2 mutation pass on latest `master`.
2. Triage remaining missed/timeout mutants (if any) and add targeted tests.
3. Re-run Stage3 after Stage2 is clean.
4. Keep this file updated after each long run to survive interruptions.
