# AGENTS.md

Guidance for AI coding agents working in this repository.

## Repository Intent

Abacus is an agent-focused policy runtime:

- TOML config -> validated + normalized in TypeScript
- Decision semantics (matching + precedence) -> implemented in Rego
- Runtime enforcement -> OPA Wasm (`@open-policy-agent/opa-wasm`)

Core goal: produce auditable `allow | ask | deny` decisions for agent actions across scopes:

- `tool`
- `skill`
- `fs`
- `net`
- `secret`

## Architecture at a Glance

- `packages/abacus/src/engine.ts`
  - Public input/output types (`Input`, `Decision`, `Action`)
  - Action typing is scope-aware (`net::use` is invalid by type)

- `packages/abacus/src/config/validate.ts`
  - Zod front-door validation for TOML shape and key semantic checks

- `packages/abacus/src/config/normalize.ts`
  - Compiles validated config into normalized rule data with priority/specificity

- `packages/abacus/src/policy/*.rego`
  - Rego policy modules and tests
  - `packages/abacus/src/policy/main.rego` is the decision entrypoint (`data.abacus.decision`)

- `packages/abacus/src/policy/runtime.ts`
  - Runtime adapter for OPA Wasm + request shaping + decision mapping

- `packages/abacus/src/index.ts`
  - Main evaluate function used by consumers

## Contract (Must Stay Stable Unless Intentionally Versioned)

### Config versioning

- `policy.schema_version`: config shape version (owned by runtime contract)
- `policy.version`: user policy version value (audit/log/display)

### Rego input envelope

Runtime passes:

- `input.config.meta`
- `input.config.rules[]`
- `input.request.{agent,scope,verb,match}`

### Rego output

Rego returns:

- `effect`
- `source`
- `reason`
- `rule_id`
- `policy_version`

Mapped to engine `Decision` as:

- `policyVersion`
- `effect`
- `reasons`
- `source`
- `ruleId`

## Precedence Semantics

Winner selection order:

1. `priority` (higher wins)
2. `specificity` (higher wins)
3. agent rank (`agent != "*"` wins over `"*"`)
4. effect rank (`deny > ask > allow`)
5. lexical `id`

Source priority constants are defined in `packages/abacus/src/config/schema.ts` (`SOURCE_PRIORITY`).

## Dev Guardrails

1. **Rego is source of truth for policy semantics.**
   - Do not add new decision/matching logic in TS as a replacement for Rego.
   - TS should validate, normalize, and call policy runtime.

2. **Do not hand-edit generated Wasm artifacts.**
   - `packages/abacus/src/policy/bundle/policy.wasm` is generated.

3. **If you change Rego modules, rebuild Wasm before integration tests.**
   - `pnpm --filter abacus run build:policy:wasm`

4. **Keep schema and policy version distinction intact.**
   - Do not collapse `schema_version` and `version` semantics.

5. **Preserve audit metadata.**
   - `source`, `reason`, `ruleId` are intentionally exposed for logs/audits.

6. **Respect strict TypeScript settings.**
   - `exactOptionalPropertyTypes`, `strict`, `noUnusedLocals`, etc.

## Common Patterns

- Add new scope-specific behavior by:
  1. Implementing a scope candidate producer in `packages/abacus/src/policy/<scope>.rego`
  2. Aggregating it in `packages/abacus/src/policy/main.rego`
  3. Adding scope Rego tests (`packages/abacus/src/policy/<scope>.test.rego`)
  4. Adding integration TOML fixture + `*.integration.test.ts`

- Add config semantics by:
  1. Updating `packages/abacus/src/config/validate.ts`
  2. Updating `packages/abacus/src/config/normalize.ts`
  3. Updating/adding tests in `packages/abacus/src/config/*.test.ts`

- For integration behavior changes, prefer fixture-driven tests in:
  - `packages/abacus/src/index.integration.test.ts`
  - `packages/abacus/src/index.matrix.integration.test.ts`
  - `packages/abacus/src/index.conflicts.integration.test.ts`
  - `packages/abacus/src/index.argv.integration.test.ts`

## Anti-Patterns to Avoid

- Re-implementing precedence logic in TS runtime path
- Coupling tests to hard-coded hash-like rule IDs unless truly necessary
- Skipping Rego tests when editing policy modules
- Modifying behavior only in integration tests without adding unit-level coverage
- Treating tar extraction warning as build failure
  - `tar: Removing leading '/' from member names` is expected with OPA bundles

## Scripts and Commands

- Unit/integration tests:
  - `pnpm run test`
  - `pnpm --filter abacus test --coverage`

- Typecheck:
  - `pnpm run typecheck` (workspace)
  - `pnpm --filter abacus run typecheck` (package)

- Rego tests:
  - `pnpm run test:rego` (workspace)
  - `pnpm --filter abacus run test:rego` (package)

- Build policy Wasm bundle:
  - `pnpm --filter abacus run build:policy:wasm`

- Full local verification (recommended before merge):
  - `pnpm run build && pnpm run test:rego && pnpm run test && pnpm run typecheck`

## Environment Notes

- Package manager: `pnpm` (pinned in `packageManager`)
- Runtime: Node.js + TypeScript
- Required external tool: `opa` CLI
- `tar` required for extracting OPA bundles

Config resolution order in runtime:

1. `ABACUS_CONFIG_PATH` env var
2. Local `abacus.toml` path based on runtime dir
3. `~/.config/abacus/abacus.toml`

## When Changing Runtime Behavior

If you touch any of these files:

- `packages/abacus/src/config/normalize.ts`
- `packages/abacus/src/config/validate.ts`
- `packages/abacus/src/policy/main.rego`
- `packages/abacus/src/policy/runtime.ts`

Then update tests at the same time and run the full verification command above.
