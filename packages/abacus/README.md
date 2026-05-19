# @ai-abacus/core

An attribute-based access control runtime for agents.

## Goal

Abacus should provide:
- a configurable rules-based engine for agent guardrails
- auditable allow/ask/deny decisions for evaluated actions
- a fast and portable runtime

## Why

Agents have permission control requirements similar to users, but with extra guardrails needed to avoid coerced behavior.

While using agents, you may want to provide access to:
- Tools (reproducible, pre-coded workflows/tools)
- Skills (re-used prompts that structure agent behavior)
- Filesystem
- Networks
- Secrets

In each case, agents shouldn't be allowed to use them without oversight.
Even in sandboxes, accessing secrets or executing code should safe and transparent.

Abacus aims to provide the configurable control plane for agents at these critical access junctures.

## Install

```bash
pnpm add @ai-abacus/core
```

## Library Usage

### Evaluate with provided policy TOML

```ts
import { evaluate } from '@ai-abacus/core'

const decision = await evaluate(
  {
    requestId: 'req-1',
    timestamp: new Date().toISOString(),
    actor: { id: 'actor-1', permissions: {} },
    action: 'tool::use',
    context: { type: 'tool', id: 'ctx-1', tool: 'bash', argv0: 'git' },
  },
  {
    configToml: `
[policy]
version = "2026-05"
permission_mode = "strict"

[default.tool.use]
"*" = "allow"
`,
  },
)
```

### Create a reusable engine

```ts
import { createEngine, parsePolicyToml } from '@ai-abacus/core'

const policy = parsePolicyToml(`
[policy]
version = "2026-05"

[default.tool.use]
"*" = "ask"
`)

const engine = await createEngine({ policy })
const decision = await engine.evaluate({
  requestId: 'req-2',
  timestamp: new Date().toISOString(),
  actor: { id: 'actor-1', permissions: {} },
  action: 'tool::use',
  context: { type: 'tool', id: 'ctx-2', tool: 'webfetch' },
})
```

### Load policy via runtime config resolution

Resolution order:

1. explicit `configPath` option
2. `ABACUS_CONFIG_PATH`
3. local `./abacus.toml` (current working directory)
4. `~/.config/abacus/abacus.toml`

Use `loadPolicy` directly if you want only parse/normalize behavior.

## Public API

- `evaluate(input, options?)`
- `createEngine(options?)`
- `loadPolicy(options?)`
- `parsePolicyToml(configToml)`
- `parseRawPolicyConfig(raw)`
- `normalizePolicy(raw)`

## Runtime Contract

### Input Schema (to Rego)

Abacus evaluates the `data.abacus.decision` entrypoint with an input envelope:

```json
{
  "config": {
    "meta": {
      "schemaVersion": 1,
      "policyVersion": "2026-05",
      "permissionMode": "strict",
      "patternDialect": "glob",
      "patternCase": "insensitive",
      "toolMatchMode": "tokenized_argv",
      "permissionModeEffect": "deny"
    },
    "rules": [
      {
        "id": "r_123",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "deny",
        "reason": "block_webfetch",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {
          "tool": "webfetch"
        }
      }
    ]
  },
  "request": {
    "agent": "build",
    "scope": "tool",
    "verb": "use",
    "match": {
      "tool": "bash",
      "argv0": "git",
      "argv": ["status"]
    }
  }
}
```

Notes:
- `schemaVersion` is the config-shape version.
- `policyVersion` is a user-controlled policy value for auditing/versioning.

### Output Schema (from Rego)

Abacus expects a structured decision payload:

```json
{
  "effect": "deny",
  "source": "override_exact",
  "reason": "block_webfetch",
  "rule_id": "r_123",
  "policy_version": "2026-05"
}
```

This is mapped into engine output:
- `policyVersion`
- `effect` (`deny` | `ask` | `allow`)
- `reasons`
- `source`
- `ruleId`

## Precedence

Rule winner selection is deterministic and follows:

1. `priority` (higher wins)
2. `specificity` (higher wins)
3. agent rank (`agent != "*"` beats `"*"`)
4. effect restrictiveness (`deny > ask > allow`)
5. lexical `id` tie-break

Current source layer priorities are normalized in TS and consumed in Rego:

- `override_exact` (700)
- `override_wildcard` (650)
- `agent_rule_exact` (600)
- `agent_rule_wildcard` (550)
- `agent_default` (500)
- `global_default` (400)
- `permission_mode` fallback

## Packaging Notes

- Runtime decisions execute against OPA Wasm (`@open-policy-agent/opa-wasm`).
- Published package includes `dist/policy/bundle/policy.wasm`; consumers do not need `opa` installed.
- `opa` and `tar` are required for maintainers when rebuilding policy Wasm before publishing.
