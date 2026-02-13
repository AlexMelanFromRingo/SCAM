# Stratum SV2 Notes

Current implementation provides a production-oriented baseline with:

- binary SV2-style framing (`extension_type:u16 + msg_type:u8 + len:u24 + payload`),
- binary payload codec (`bincode`) plus header/payload message-type consistency checks,
- protocol state machine (`SetupConnection` -> `OpenStandardMiningChannel` -> active),
- per-connection session stats (accepted/rejected shares + target updates),
- bounded per-channel job cache,
- share validation (`share_target` + `network_target`),
- VarDiff share target retuning (`SetTarget`) based on recent accepted-share cadence,
- reject-budget circuit breaker (`max_rejected_shares`) that closes abusive sessions,
- idle keepalive loop and idle timeout handling,
- multi-client threaded server in `scam-node stratum-serve`,
- tip-change driven job refresh for connected clients,
- automatic new-job issue after valid block share.
- explicit local role split wiring:
- Template Provider (`RuntimeTemplateProvider`) in node runtime path,
- Job Declarator (`SequentialJobDeclarator`) for monotonic job IDs,
- Translator (`IdentityTranslator`) for remote job message decoding.
- optional encrypted transport channel (`--secure-transport` + `stratum_secure_transport`) using ECDH + AEAD framing.
- configurable secure rekey interval (`--secure-rekey-interval-messages` + `stratum_secure_rekey_interval_messages`).

All operational defaults are available in network config as `stratum_*` fields.
CLI flags in `stratum-serve` override config values when provided.

## Commands

Pool server:

```bash
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347 \
  --share-target-hex ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --min-share-target-hex 00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --max-share-target-hex ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --vardiff-target-shares-per-minute 6 \
  --vardiff-retarget-interval-shares 24 \
  --max-rejected-shares 64 \
  --read-timeout-sec 2 \
  --keepalive-sec 30 \
  --idle-timeout-sec 180 \
  --max-jobs-per-channel 64 \
  --max-active-clients 256 \
  --secure-transport \
  --secure-rekey-interval-messages 10000
```

Worker (manual pool endpoint, no DNS requirement):

```bash
cargo run -p scam-node -- stratum-mine \
  --pool 127.0.0.1:3347 \
  --user miner01 \
  --max-shares 10 \
  --secure-transport \
  --secure-rekey-interval-messages 10000
```

## Scope

This is a robust SV2 subset suitable for integration testing and external miner connectivity.
A full pool-grade SV2 deployment still needs:

- externalized role services and failure-domain split across independent pool components,
- production Noise-spec transport security (current encrypted mode is a Noise-like baseline),
- exhaustive interoperability matrix testing with third-party SV2 stacks.

Tracking file: `docs/SV2_POOL_GRADE_GAP.md`.
