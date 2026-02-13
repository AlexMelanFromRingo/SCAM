# SV2 Pool-Grade Gap Plan

Current SCAM implementation provides a robust SV2 subset suitable for integration and controlled deployments.
This file tracks the remaining items for full pool-grade SV2 readiness.

## 1) Role Split

- [x] Introduce explicit Template Provider role (local runtime provider baseline).
- [x] Introduce explicit Job Declarator role (monotonic sequential declarator).
- [x] Introduce explicit Translator role (remote job message translator).
- [ ] Externalize roles into independent pool services with network boundaries.
- [ ] Define role interfaces and failure domains.

## 2) Transport Security

- [x] Add encrypted transport baseline (ECDH handshake + AEAD frame protection).
- [ ] Integrate full Noise-spec encrypted channels.
- [ ] Add key lifecycle and rotation policy.
- [ ] Add secure handshake/error handling tests.

## 3) Interoperability Matrix

- [ ] Build compatibility matrix with third-party SV2 stacks.
- [ ] Add message corpus replay against external implementations.
- [ ] Add conformance report in CI artifacts.

## 4) Operational Readiness

- [ ] Add role-specific telemetry dashboards.
- [ ] Add staged rollout policy for protocol changes.
- [ ] Publish incident runbook for pool-role failures.
