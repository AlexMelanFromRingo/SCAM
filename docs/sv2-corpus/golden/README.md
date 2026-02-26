# SV2 Golden Corpus Expectations

This directory stores deterministic expectations for SCAM local SV2 conformance targets.

- `expectations.json`: baseline contract for `scripts/sv2-golden-verify.py`.

Update procedure:

1. Run:

```bash
scripts/sv2-golden-freeze.sh
```

2. Review diff in `docs/sv2-corpus/golden/expectations.json`.
3. If expected, commit together with related protocol changes.

Verification:

```bash
scripts/sv2-conformance-matrix.sh
python3 scripts/sv2-golden-verify.py \
  --input-dir target/sv2-conformance \
  --golden docs/sv2-corpus/golden/expectations.json
```
