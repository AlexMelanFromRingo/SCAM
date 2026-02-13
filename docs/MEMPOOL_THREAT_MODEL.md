# Mempool Threat Model (SCAM)

Date: 2026-02-12
Scope: double-spend race behavior and DoS pressure around conflicting UTXO spends.

## Baseline Policy

- Conflict rule: fee-aware replacement only.
- Miner template policy: CPFP package-aware selection (high-fee child can pull low-fee parent).
- Replacement conditions:
  - incoming feerate must be strictly higher,
  - incoming absolute fee must exceed previous fee by configured minimum delta,
  - replacement package must stay under configured descendant limit.
- Structural tx sanity checks enforced before pool admission.
- Orphan pool is bounded and TTL-limited.

## Threats and Current Mitigations

1. `txid` grinding to win replacement races.
- Risk: attacker mutates tx fields to mine a lower hash and displace victim tx.
- Mitigation: no hash-order rule is used. Replacement is fee/feerate gated only.
- Residual risk: fee-spam is still possible, but now economically bounded.

2. Low-fee pinning of victim UTXO.
- Risk: attacker pins an outpoint with low-fee tx, delaying confirmation.
- Mitigation: higher feerate + min fee delta replacement is allowed.
- Residual risk: if a relay subset ignores replacement policy, local divergence in mempools can persist until mining.

3. Replacement package explosion (descendant DoS).
- Risk: replacing one tx could trigger eviction of a large descendant graph.
- Mitigation: replacement descendant cap rejects oversized replacement sets.
- Residual risk: attacker can still fill mempool with independent chains up to limits.

4. Full-pool eviction games.
- Risk: attacker submits borderline-fee txs to churn evictions.
- Mitigation: full pool evicts only lowest feerate entries; lower/equal-feerate incoming tx is rejected.
- Residual risk: churn remains possible at sustained higher feerates.

5. Orphan amplification.
- Risk: attacker floods missing-parent txs.
- Mitigation: orphan pool has explicit size limit + TTL expiry + dependency resolution.
- Residual risk: targeted churn can still consume bounded resources.

## Security Invariants to Preserve

- No acceptance of coinbase tx in mempool.
- No zero-value outputs.
- No duplicate inputs in a tx.
- No invalid compressed key format in tx inputs.
- Replacement only through explicit fee/feerate policy.

## Test Coverage Mapping

- `crates/mempool/src/lib.rs`:
  - conflict replacement accept/reject paths,
  - descendant-cap rejection,
  - fee-policy enforcement,
  - full-pool eviction logic,
  - structural sanity rejections,
  - orphan pool bounds/expiry/dependency release.

## Recent Hardening Completed

- Added per-peer replacement rate limits in networking path (`scam-p2p` gossip delta path with peer penalty/banning).
- Added metrics/telemetry hooks for replacement and orphan churn (`MempoolTelemetry`, `OrphanPoolTelemetry`, `GossipTelemetry`).
- Added peer-scoped replacement quota integration in soak runtime admission path (`node soak`) where tx admission uses mempool + orphan pool + gossip relay limits.
- Added telemetry snapshot persistence for long-run soak analysis (`node soak --telemetry-out <file>` JSONL snapshots).

## Recommended Next Hardening

- Add threshold-based alerting script/checks over persisted telemetry snapshots.
- Extend peer-scoped replacement quotas from soak admission loop to long-lived socket P2P mempool runtime as that path is expanded.
