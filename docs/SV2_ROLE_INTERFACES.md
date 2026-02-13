# SV2 Role Interfaces and Failure Domains

This document freezes the SCAM role-service interfaces used by pool-role split mode.

## 1) Services

- Template Provider service:
  - command: `scam-node sv2-template-provider`
  - responsibility: build coinbase + mining template material.
- Job Declarator service:
  - command: `scam-node sv2-job-declarator`
  - responsibility: monotonic `job_id` assignment per request stream.
- Translator service:
  - command: `scam-node sv2-translator`
  - responsibility: parse remote SV2 job messages into local mining job structures.

## 2) Wire Contract

Transport:
- TCP, newline-delimited JSON request/response.

Request/response contracts:
- Template Provider:
  - request: `TemplateProviderRequest`
  - response: `TemplateProviderResponse`
- Job Declarator:
  - request: `JobDeclaratorRequest`
  - response: `JobDeclaratorResponse`
- Translator:
  - request: `TranslatorRequest`
  - response: `TranslatorResponse`

Canonical definitions live in:
- `crates/node/src/main.rs`
  - `TemplateProviderRequest`
  - `TemplateProviderResponse`
  - `JobDeclaratorRequest`
  - `JobDeclaratorResponse`
  - `TranslatorRequest`
  - `TranslatorResponse`

## 3) Failure Domains

- Template Provider failure:
  - impact: new jobs cannot be composed.
  - expected behavior: stratum server reports role-call failure and stops issuing new jobs.
- Job Declarator failure:
  - impact: template exists but cannot be assigned stable `job_id`.
  - expected behavior: server fails request path, existing channels keep current jobs until refresh.
- Translator failure:
  - impact: worker cannot decode remote job updates.
  - expected behavior: worker keeps current local state and logs translation errors.

Isolation boundary:
- each role runs as an independent process and can be deployed on separate hosts/networks.

## 4) Telemetry

Each role supports telemetry snapshots via:
- `--telemetry-out <path>`

Snapshot shape:
- `timestamp_unix_sec`
- `role`
- `requests_total`
- `success_total`
- `error_total`

Dashboard generator:
- `scripts/role-telemetry-dashboard.py`

