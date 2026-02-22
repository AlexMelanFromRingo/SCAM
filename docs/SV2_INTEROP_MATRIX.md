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

3. Optional JSON-driven target list (recommended for multi-vendor runs):

```bash
SV2_EXTERNAL_TARGETS_FILE=docs/sv2-interop-targets.example.json \
scripts/sv2-conformance-matrix.sh
```

The harness writes per-target run status metadata to:

- `target/sv2-conformance/external-target-results.jsonl`

4. Outputs:

- `target/sv2-conformance/*.json` per-stack reports
- `target/sv2-conformance/summary.json`
- `target/sv2-conformance/matrix.md`
- `target/sv2-conformance/external-target-results.jsonl` (if external targets were configured)

CI uploads the same directory as artifact (`sv2-conformance`).
