# SV2 Interoperability Matrix Workflow

SCAM provides an executable conformance/matrix pipeline:

1. Run matrix harness:

```bash
scripts/sv2-conformance-matrix.sh
```

2. Optional third-party targets:

```bash
SV2_EXTERNAL_TARGETS="stackA,203.0.113.10:3347,false,legacy,;stackB,203.0.113.11:3347,true,noise-xx,abcdef..." \
scripts/sv2-conformance-matrix.sh
```

Extended tuple format is supported:

```bash
SV2_EXTERNAL_TARGETS="name,host:port,secure,mode,secret_hex,expected,vendor,version"
```

where:

- `expected` is `pass` or `fail`
- `vendor`/`version` are metadata fields written to result artifacts.

Full tuple (for strict automation and per-vendor quirks capture):

```text
name,endpoint,secure,mode,secret_hex,expected,vendor,version,role,corpus,read_timeout_sec,connect_timeout_sec,connect_retries,connect_retry_delay_ms,expect_set_target,min_job_messages,workaround,notes,required_observed_kinds,forbidden_observed_kinds,require_setup_version,require_setup_flags_mask,forbid_setup_flags_mask,setup_protocol,setup_min_version,setup_max_version,setup_flags
```

3. Optional JSON-driven target list (recommended for multi-vendor runs):

```bash
SV2_EXTERNAL_TARGETS_FILE=docs/sv2-interop-targets.example.json \
scripts/sv2-conformance-matrix.sh
```

`docs/sv2-interop-targets.example.json` now supports per-target fields:

- `role`
- `corpus`
- `read_timeout_sec`
- `connect_timeout_sec`
- `connect_retries`
- `connect_retry_delay_ms`
- `expect_set_target`
- `min_job_messages`
- `workaround`
- `notes`
- `required_observed_kinds` (array of message kind strings)
- `forbidden_observed_kinds` (array of message kind strings)
- `require_setup_version` (optional, strict `SetupConnectionSuccess.used_version` gate)
- `require_setup_flags_mask` (optional bitmask, all bits must be present in `SetupConnectionSuccess.flags`)
- `forbid_setup_flags_mask` (optional bitmask, no bits may be present in `SetupConnectionSuccess.flags`)
- `setup_protocol` (default `2`)
- `setup_min_version` (default `2`)
- `setup_max_version` (default `2`)
- `setup_flags` (default `0`)
- `enabled` (optional; `false` skips the row)

The harness writes per-target run status metadata to:

- `target/sv2-conformance/external-target-results.jsonl`

Connection-hardening knobs for flaky external endpoints:

- `SV2_CONFORMANCE_CONNECT_TIMEOUT_SEC` (default `5`)
- `SV2_CONFORMANCE_CONNECT_RETRIES` (default `4`, extra attempts after the first)
- `SV2_CONFORMANCE_CONNECT_RETRY_DELAY_MS` (default `300`)
- `SV2_CONFORMANCE_READ_TIMEOUT_SEC` (default `3`)
- `SV2_CONFORMANCE_MIN_JOB_MESSAGES` (default `1`)
- `SV2_CONFORMANCE_EXPECT_SET_TARGET` (default `true`)
- `SV2_CONFORMANCE_REQUIRED_OBSERVED_KINDS` (semicolon-separated, optional)
- `SV2_CONFORMANCE_FORBIDDEN_OBSERVED_KINDS` (semicolon-separated, optional)
- `SV2_CONFORMANCE_REQUIRE_SETUP_VERSION` (optional)
- `SV2_CONFORMANCE_REQUIRE_SETUP_FLAGS_MASK` (default `0`)
- `SV2_CONFORMANCE_FORBID_SETUP_FLAGS_MASK` (default `0`)
- `SV2_CONFORMANCE_SETUP_PROTOCOL` (default `2`)
- `SV2_CONFORMANCE_SETUP_MIN_VERSION` (default `2`)
- `SV2_CONFORMANCE_SETUP_MAX_VERSION` (default `2`)
- `SV2_CONFORMANCE_SETUP_FLAGS` (default `0`)

Target tuple validation is strict for `secure` (`true|false`), `mode` (`legacy|noise-xx`), and
`expected` (`pass|fail`) to avoid false-positive matrix rows.

4. Outputs:

- `target/sv2-conformance/*.json` per-stack reports
- `target/sv2-conformance/summary.json`
- `target/sv2-conformance/matrix.md`
- `target/sv2-conformance/external-target-results.jsonl` (if external targets were configured)

`matrix.md` now contains:

- built-in/local conformance table,
- external matrix rows with expected/result metadata,
- vendor quirks/workarounds section derived from external rows.

CI uploads the same directory as artifact (`sv2-conformance`).

5. Optional GitHub Actions run against external stacks:

- Workflow: `.github/workflows/sv2-external-interop.yml`
- Trigger: manual (`workflow_dispatch`)
- Required secret: `SV2_EXTERNAL_TARGETS_JSON` (same JSON schema as `SV2_EXTERNAL_TARGETS_FILE`)
- Artifact: `sv2-external-conformance`

6. Final release gate:

```bash
scripts/sv2-release-gate.sh
```

Optional strict mode (require at least one external row):

```bash
REQUIRE_EXTERNAL=true \
SV2_EXTERNAL_TARGETS_FILE=docs/sv2-interop-targets.example.json \
scripts/sv2-release-gate.sh
```

Enable golden baseline verification in release gate:

```bash
VERIFY_GOLDEN=true \
GOLDEN_EXPECTATIONS=docs/sv2-corpus/golden/expectations.json \
scripts/sv2-release-gate.sh
```

Release gate artifacts:

- `target/sv2-release-gate/matrix/*`
- `target/sv2-release-gate/release-gate.json`
- `target/sv2-release-gate/golden-verify.json` (when `VERIFY_GOLDEN=true`)

Golden corpus maintenance:

```bash
scripts/sv2-golden-freeze.sh
python3 scripts/sv2-golden-verify.py \
  --input-dir target/sv2-conformance \
  --golden docs/sv2-corpus/golden/expectations.json
```

7. Direct corpus replay with strict observed-kind gate:

```bash
POOL=203.0.113.20:3347 \
CORPUS=docs/sv2-corpus/full-spec-submit.json \
MIN_JOB_MESSAGES=1 \
EXPECT_SET_TARGET=true \
REQUIRE_OBSERVED_KINDS="SetupConnectionSuccess;OpenStandardMiningChannelSuccess;SetTarget" \
FORBID_OBSERVED_KINDS="SetupConnectionError;OpenStandardMiningChannelError" \
scripts/sv2-corpus-replay.sh
```
