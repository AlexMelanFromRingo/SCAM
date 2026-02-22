#!/usr/bin/env bash
set -euo pipefail

PRESET="${1:-}"
ACTION="${2:-up}"
PRESET_DIR="${PRESET_DIR:-scripts/presets}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/run-preset.sh list
  scripts/run-preset.sh <preset> {up|down|status|clean}

Examples:
  scripts/run-preset.sh lab-solo-local up
  scripts/run-preset.sh lab-solo-local status
  scripts/run-preset.sh lab-node-only down
USAGE
}

if [[ -z "${PRESET}" ]] || [[ "${PRESET}" == "help" ]] || [[ "${PRESET}" == "-h" ]] || [[ "${PRESET}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${PRESET}" == "list" ]]; then
  if [[ ! -d "${PRESET_DIR}" ]]; then
    echo "[preset] no preset directory: ${PRESET_DIR}" >&2
    exit 1
  fi
  find "${PRESET_DIR}" -maxdepth 1 -type f -name '*.env' -printf '%f\n' | sed -E 's/\.env$//' | sort
  exit 0
fi

if [[ ! "${ACTION}" =~ ^(up|down|status|clean)$ ]]; then
  echo "[preset] invalid action: ${ACTION}" >&2
  usage
  exit 2
fi

PRESET_FILE="${PRESET_DIR}/${PRESET}.env"
if [[ ! -f "${PRESET_FILE}" ]]; then
  echo "[preset] preset not found: ${PRESET_FILE}" >&2
  echo "[preset] available presets:" >&2
  "${0}" list >&2 || true
  exit 2
fi

set -a
# shellcheck source=/dev/null
source "${PRESET_FILE}"
set +a

LAUNCH_SCRIPT="${LAUNCH_SCRIPT:-scripts/local-test-lab.sh}"
if [[ ! -f "${LAUNCH_SCRIPT}" ]]; then
  echo "[preset] launch script not found: ${LAUNCH_SCRIPT}" >&2
  exit 2
fi

echo "[preset] ${PRESET} -> ${LAUNCH_SCRIPT} ${ACTION}"
if [[ -n "${CLUSTER_DIR:-}" ]]; then
  echo "[preset] cluster dir: ${CLUSTER_DIR}"
fi
if [[ -n "${NETWORK:-}" ]]; then
  echo "[preset] network: ${NETWORK}"
fi

bash "${LAUNCH_SCRIPT}" "${ACTION}"
