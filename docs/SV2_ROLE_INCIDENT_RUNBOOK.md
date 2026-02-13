# SV2 Role Incident Runbook

Scope: Template Provider, Job Declarator, Translator process failures and secure transport incidents.

## 1) Triage

- Confirm impacted role:
  - template errors -> Template Provider
  - job-id assignment failures -> Job Declarator
  - remote-job decode failures -> Translator
  - handshake/decrypt failures -> secure transport path
- Capture:
  - recent role telemetry JSONL snapshots
  - stratum server logs
  - conformance report (`sv2-conformance` output)

## 2) Immediate Mitigation

- If role process is down:
  - restart role service process,
  - if restart fails, switch stratum to local role fallback (remove remote role endpoint flags).
- If secure transport regression:
  - switch `--secure-transport-mode legacy` temporarily,
  - keep secure mode enabled only after noise_xx issue is fixed.
- If key mismatch:
  - validate configured static secret/public mapping,
  - rotate keys with `scam-node stratum-key-rotate`.

## 3) Recovery Steps

1. Restore service availability (process restart or fallback mode).
2. Run conformance probe:
   - `scam-node sv2-conformance --pool <endpoint> ...`
3. Validate telemetry trend:
   - `scripts/role-telemetry-dashboard.py --input <jsonl> --out <dashboard.md>`
4. Re-enable intended mode and watch error counters.

## 4) Postmortem Checklist

- Root cause documented.
- Blast radius documented (miners, shares, block production impact).
- Corrective action merged + tested.
- Rollout policy updated if gate gaps were found.

