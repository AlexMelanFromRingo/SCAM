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

3. Outputs:

- `target/sv2-conformance/*.json` per-stack reports
- `target/sv2-conformance/summary.json`
- `target/sv2-conformance/matrix.md`

CI uploads the same directory as artifact (`sv2-conformance`).

