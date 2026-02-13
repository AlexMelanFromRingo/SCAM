# Stratum SV2 Notes

Current implementation provides a production-oriented baseline with:

- framed transport (`u32` big-endian length + JSON payload),
- protocol state machine (`SetupConnection` -> `OpenStandardMiningChannel` -> active),
- per-connection session stats (accepted/rejected shares),
- bounded per-channel job cache,
- share validation (`share_target` + `network_target`),
- multi-client threaded server in `scam-node stratum-serve`,
- automatic new-job issue after valid block share.

## Commands

```bash
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347 \
  --share-target-hex ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --max-jobs-per-channel 64 \
  --max-clients 16
```

## Scope

This is a robust SV2 subset suitable for integration testing and external miner connectivity.
A full pool-grade SV2 deployment still needs full role separation, template distribution,
transport security, and full interoperability matrix testing against third-party implementations.
