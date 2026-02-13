# Stratum SV2 Notes

Current SCAM implementation provides:

- binary SV2-style framing (`extension_type:u16 + msg_type:u8 + len:u24 + payload`),
- binary payload codec (`bincode`) with type-consistency checks,
- protocol state machine (`SetupConnection` -> `OpenStandardMiningChannel` -> active),
- per-session stats and reject-budget close policy,
- VarDiff target retuning + target bounds,
- multi-client server (`stratum-serve`) and worker client (`stratum-mine`),
- explicit role-split services:
  - `sv2-template-provider`
  - `sv2-job-declarator`
  - `sv2-translator`
- secure transport modes:
  - `legacy` (ECDH + AEAD baseline),
  - `noise_xx` (Noise `XX_25519_ChaChaPoly_BLAKE2s`),
- configurable message-count rekey intervals,
- key lifecycle commands:
  - `stratum-keygen`
  - `stratum-key-rotate`,
- conformance/corpus tooling:
  - `sv2-conformance`
  - `scripts/sv2-corpus-replay.sh`
  - `scripts/sv2-conformance-matrix.sh`.

## Key Commands

Generate Noise static keys:

```bash
cargo run -p scam-node -- stratum-keygen \
  --secret-out data/stratum-keys/server.secret.hex \
  --public-out data/stratum-keys/server.public.hex
```

Rotate keys (archives old keys, writes new pair):

```bash
cargo run -p scam-node -- stratum-key-rotate \
  --secret-path data/stratum-keys/server.secret.hex \
  --public-path data/stratum-keys/server.public.hex \
  --archive-dir data/stratum-keys/archive
```

Pool server with secure noise mode:

```bash
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <hex32>
```

Worker client:

```bash
cargo run -p scam-node -- stratum-mine \
  --pool 127.0.0.1:3347 \
  --user miner01 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <hex32>
```

Conformance report:

```bash
cargo run -p scam-node -- sv2-conformance \
  --pool 127.0.0.1:3347 \
  --stack-name local \
  --corpus docs/sv2-corpus/default.json \
  --out target/sv2-conformance/local.json
```

Tracking docs:

- `docs/SV2_POOL_GRADE_GAP.md`
- `docs/SV2_ROLE_INTERFACES.md`
- `docs/SV2_INTEROP_MATRIX.md`

