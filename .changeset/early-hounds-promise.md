---
"@ai-abacus/core": minor
---

Initial public release of `@ai-abacus/core`.

This release ships the core policy runtime for agent actions, including:

- TOML policy parsing, validation, and normalization
- Rego-based decision semantics compiled to OPA Wasm
- A typed TypeScript library API (`evaluate`, `createEngine`, `loadPolicy`, `parsePolicyToml`)
- Audit-friendly decision metadata (`effect`, `source`, `reason`, `ruleId`, `policyVersion`)
- Integration and policy test coverage for precedence and scope behavior
