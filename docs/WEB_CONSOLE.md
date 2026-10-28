# Web Console (Explorer + Wallet)

SCAM includes a browser UI served by the node (`scam-node serve --rpc "..."`).

The UI is in `web/` and provides:
- explorer view (status, latest blocks, block lookup, tx lookup),
- mempool telemetry snapshot view (from relay telemetry JSONL),
- live updates via SSE (`GET /events`) with polling fallback,
- wallet flows over RPC (`new`, `address`, `balance`, `send-preview`, `send`, `decode`, `qr`).

## 1) Start Node Runtime

Prepare runtime DB first:

```bash
cargo run -p scam-node -- node \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb
```

## 2) Start the node with the RPC + UI server

The console runs inside the node process, on the node's own chain and
mempool (a running node owns its data directory; a separate `rpc-serve` on
the same files is refused):

```bash
cargo run -p scam-node -- serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 0.0.0.0:18444 \
  --telemetry-out data/relay.telemetry.jsonl \
  --rpc "--bind 127.0.0.1:18080 --ui-dir web --relay-telemetry data/relay.telemetry.jsonl"
```

Open:

```text
http://127.0.0.1:18080/
```

## 3) RPC Endpoint Map

GET:
- `/health`
- `/status`
- `/block/<height>`
- `/tx/<height>/<index>`
- `/mempool`
- `/events` (SSE stream: periodic `snapshot` events)

POST:
- `/wallet/new`
- `/wallet/address`
- `/wallet/decode`
- `/wallet/balance`
- `/wallet/balance-by-address`
- `/wallet/send-preview`
- `/wallet/send`
- `/tx/submit`
- `/wallet/qr`

## 4) Security Notes

- Wallet RPC methods can include mnemonic material in request bodies.
- Run RPC/UI only on trusted interfaces (default bind is loopback).
- Keep this endpoint behind network controls for any multi-user environment.

## 5) Stratum vs RPC

- RPC/UI is for operator tooling, explorer, and wallet operations.
- Mining jobs and share submission should use Stratum/SV2 commands (`serve --stratum`, `stratum-mine`, role services).
