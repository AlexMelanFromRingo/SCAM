#!/usr/bin/env bash
set -euo pipefail

# Stage-oriented mutation entrypoint to keep long integration-heavy crates
# separate from core consensus/unit-targeted mutation runs.
#
# Usage:
#   scripts/mutation-staged.sh            # run stage1, stage2, stage3
#   scripts/mutation-staged.sh stage1     # run only one stage
#   scripts/mutation-staged.sh stage2
#   scripts/mutation-staged.sh stage3

stage="${1:-all}"
root_out="${MUTATION_STAGE_OUT_ROOT:-target/mutants-stage}"

run_stage() {
  local stage_name="$1"
  local out_dir="$2"
  local packages="$3"

  echo "[mutation-staged] ${stage_name} -> ${out_dir}"
  if [[ -n "${packages}" ]]; then
    MUTATION_OUT_DIR="${out_dir}" MUTATION_PACKAGES="${packages}" scripts/mutation-baseline.sh
  else
    MUTATION_OUT_DIR="${out_dir}" scripts/mutation-baseline.sh
  fi
}

case "${stage}" in
  stage1)
    run_stage "stage1(core/consensus/chain/mempool/miner)" \
      "${root_out}/stage1" \
      "scam-core scam-consensus scam-chain scam-mempool scam-miner"
    ;;
  stage2)
    run_stage "stage2(stratum/p2p/node)" \
      "${root_out}/stage2" \
      "scam-stratum scam-p2p scam-node"
    ;;
  stage3)
    run_stage "stage3(full-workspace)" \
      "${root_out}/stage3" \
      ""
    ;;
  all)
    run_stage "stage1(core/consensus/chain/mempool/miner)" \
      "${root_out}/stage1" \
      "scam-core scam-consensus scam-chain scam-mempool scam-miner"
    run_stage "stage2(stratum/p2p/node)" \
      "${root_out}/stage2" \
      "scam-stratum scam-p2p scam-node"
    run_stage "stage3(full-workspace)" \
      "${root_out}/stage3" \
      ""
    ;;
  *)
    echo "unknown stage '${stage}' (expected: stage1|stage2|stage3|all)" >&2
    exit 2
    ;;
esac

