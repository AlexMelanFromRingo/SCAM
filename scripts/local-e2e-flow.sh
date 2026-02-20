#!/usr/bin/env bash
set -euo pipefail

# Full local E2E flow:
# 1) launch 2-node lab with live relay connectivity,
# 2) wait for miner funds on wallet-01,
# 3) submit /wallet/send on node-0 (wallet-01 -> wallet-02),
# 4) verify tx enters mempool,
# 5) verify wallet-02 balance updates on node-1 after mining+propagation.
#
# Usage:
#   scripts/local-e2e-flow.sh
#
# Optional env:
#   CLUSTER_DIR=target/local-e2e-flow
#   CONFIG_TEMPLATE=config/devnet.toml
#   CONFIG_E2E=target/local-e2e-flow/devnet-e2e.toml
#   SEND_AMOUNT=1000000
#   SEND_FEE=500
#   WAIT_TIMEOUT_SEC=120
#   POLL_INTERVAL_SEC=1
#   KEEP_RUNNING=false
#   BUILD=true
#   SCAM_NODE_BIN=target/release/scam-node

CLUSTER_DIR="${CLUSTER_DIR:-target/local-e2e-flow}"
CONFIG_TEMPLATE="${CONFIG_TEMPLATE:-config/devnet.toml}"
CONFIG_E2E="${CONFIG_E2E:-${CLUSTER_DIR}/devnet-e2e.toml}"
SEND_AMOUNT="${SEND_AMOUNT:-1000000}"
SEND_FEE="${SEND_FEE:-500}"
WAIT_TIMEOUT_SEC="${WAIT_TIMEOUT_SEC:-120}"
POLL_INTERVAL_SEC="${POLL_INTERVAL_SEC:-1}"
KEEP_RUNNING="${KEEP_RUNNING:-false}"
BUILD="${BUILD:-true}"
SCAM_NODE_BIN="${SCAM_NODE_BIN:-}"

is_true() {
  local raw="${1:-false}"
  local val="${raw,,}"
  [[ "${val}" == "1" || "${val}" == "true" || "${val}" == "yes" || "${val}" == "on" ]]
}

cleanup() {
  if is_true "${KEEP_RUNNING}"; then
    return 0
  fi
  CLUSTER_DIR="${CLUSTER_DIR}" ./scripts/local-test-lab.sh down >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "${CLUSTER_DIR}"

if [[ ! -f "${CONFIG_TEMPLATE}" ]]; then
  echo "[e2e] missing config template: ${CONFIG_TEMPLATE}" >&2
  exit 2
fi

cp "${CONFIG_TEMPLATE}" "${CONFIG_E2E}"
python3 - "${CONFIG_E2E}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = re.sub(r"(?m)^coinbase_maturity\s*=\s*\d+\s*$", "coinbase_maturity = 1", text)
path.write_text(text, encoding="utf-8")
PY

echo "[e2e] launching local test lab"
env \
  CLUSTER_DIR="${CLUSTER_DIR}" \
  CONFIG="${CONFIG_E2E}" \
  RUN_SYNC_LOOP=false \
  RELAY_OUTBOUND_CONNECT=true \
  BUILD="${BUILD}" \
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" \
  ./scripts/local-test-lab.sh up

WALLETS_ENV="${CLUSTER_DIR}/wallets/wallets.env"
ENDPOINTS_FILE="${CLUSTER_DIR}/endpoints.tsv"
if [[ ! -f "${WALLETS_ENV}" ]]; then
  echo "[e2e] missing wallets env: ${WALLETS_ENV}" >&2
  exit 1
fi
if [[ ! -f "${ENDPOINTS_FILE}" ]]; then
  echo "[e2e] missing endpoints file: ${ENDPOINTS_FILE}" >&2
  exit 1
fi

set -a
# shellcheck source=/dev/null
source "${WALLETS_ENV}"
set +a

NODE0_RPC_PORT="$(awk -F '\t' 'NR>1 && $1==0 {print $3}' "${ENDPOINTS_FILE}" | head -n1)"
NODE1_RPC_PORT="$(awk -F '\t' 'NR>1 && $1==1 {print $3}' "${ENDPOINTS_FILE}" | head -n1)"
if [[ -z "${NODE0_RPC_PORT}" || -z "${NODE1_RPC_PORT}" || "${NODE0_RPC_PORT}" == "-" || "${NODE1_RPC_PORT}" == "-" ]]; then
  echo "[e2e] invalid rpc ports in ${ENDPOINTS_FILE}" >&2
  exit 1
fi

python3 - "${NODE0_RPC_PORT}" "${NODE1_RPC_PORT}" "${SEND_AMOUNT}" "${SEND_FEE}" "${WAIT_TIMEOUT_SEC}" "${POLL_INTERVAL_SEC}" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

node0_rpc = int(sys.argv[1])
node1_rpc = int(sys.argv[2])
amount = int(sys.argv[3])
fee = int(sys.argv[4])
timeout_sec = int(sys.argv[5])
poll_sec = float(sys.argv[6])

wallet_01_mnemonic = __import__("os").environ["WALLET_01_MNEMONIC"]
wallet_01_address = __import__("os").environ["WALLET_01_ADDRESS"]
wallet_02_address = __import__("os").environ["WALLET_02_ADDRESS"]

def rpc_post(port: int, path: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode(), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"raw": body}
        return err.code, parsed

def rpc_get(port: int, path: str):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.getcode(), json.loads(resp.read().decode("utf-8"))

def wait_until(predicate, description: str):
    deadline = time.time() + timeout_sec
    last = None
    while time.time() < deadline:
        ok, last = predicate()
        if ok:
            return last
        time.sleep(poll_sec)
    raise RuntimeError(f"timeout waiting for {description}; last={last}")

def wallet_balance_by_address(port: int, address: str):
    status, body = rpc_post(port, "/wallet/balance-by-address", {"address": address})
    if status != 200:
        return None
    return body

print("[e2e] waiting for mature mining funds on wallet-01 (node-0)")
required_sender = amount + fee
sender_balance = wait_until(
    lambda: (
        lambda b: (b is not None and int(b.get("spendable", 0)) >= required_sender, b)
    )(wallet_balance_by_address(node0_rpc, wallet_01_address)),
    "wallet-01 spendable funds",
)
print(
    f"[e2e] wallet-01 spendable={sender_balance['spendable']} at tip={sender_balance['tip_height']}"
)

print("[e2e] submitting /wallet/send on node-0")
send_payload = {
    "mnemonic": wallet_01_mnemonic,
    "passphrase": "",
    "account": 0,
    "index": 0,
    "to": wallet_02_address,
    "amount": amount,
    "fee": fee,
}
status, send_body = rpc_post(node0_rpc, "/wallet/send", send_payload)
if status != 200:
    raise RuntimeError(f"/wallet/send failed: status={status} body={send_body}")
txid = send_body["txid"]
print(f"[e2e] submitted txid={txid} fee={send_body['fee']}")

print("[e2e] waiting for tx to appear in node-0 mempool")
wait_until(
    lambda: (
        lambda body: (txid in body.get("txids", []), body)
    )(rpc_get(node0_rpc, "/mempool")[1]),
    "tx visibility in /mempool",
)

print("[e2e] waiting for wallet-02 balance update on node-1")
receiver_balance = wait_until(
    lambda: (
        lambda b: (b is not None and int(b.get("spendable", 0)) >= amount, b)
    )(wallet_balance_by_address(node1_rpc, wallet_02_address)),
    "wallet-02 credited balance on node-1",
)

print("[e2e] success")
print(
    json.dumps(
        {
            "txid": txid,
            "receiver_spendable": receiver_balance["spendable"],
            "receiver_tip_height": receiver_balance["tip_height"],
            "node0_rpc": node0_rpc,
            "node1_rpc": node1_rpc,
        },
        ensure_ascii=False,
    )
)
PY

echo "[e2e] done"
if is_true "${KEEP_RUNNING}"; then
  echo "[e2e] lab kept running (KEEP_RUNNING=true)"
  echo "[e2e] stop manually: CLUSTER_DIR=${CLUSTER_DIR} ./scripts/local-test-lab.sh down"
fi
