# @ai-abacus/plugin-opencode

OpenCode plugin that routes tool usage through `@ai-abacus/core` before execution.

## What it does

- Evaluates `tool::use` for every tool call.
- Evaluates additional scope-specific candidates when possible:
  - `skill::use` for the `skill` tool
  - `net::get` for `webfetch`
  - filesystem actions for `read`, `edit`, `write`, `glob`, `grep`, and `apply_patch`
- Enforces `deny` decisions in `tool.execute.before` by throwing an error.
- Handles `ask` with configurable behavior. Default is `allow-log`.

## Install

```bash
pnpm add @ai-abacus/plugin-opencode
```

## Configure

Add plugin in `opencode.json`.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "@ai-abacus/plugin-opencode",
      {
        "mode": "enforce-full",
        "askBehavior": "allow-log",
        "configPath": "./abacus.toml"
      }
    ]
  ]
}
```

## Options

- `mode`: `shadow` | `enforce-deny` | `enforce-full`
  - `shadow`: evaluate and log only
  - `enforce-deny`: block `deny`, allow `ask`
  - `enforce-full`: block `deny`, and apply `askBehavior` for `ask`
- `askBehavior`: `allow-log` | `deny` (default `allow-log`)
- `configPath`: abacus config path (relative to OpenCode project directory)
- `configToml` / `policy`: inline TOML policy string
- `wasmPath`: explicit path to `policy.wasm`
- `agentDefault`: fallback agent name when OpenCode session agent is unknown (default `build`)
- `logDecisions`: log decisions via `client.app.log` (default `true`)

## Notes

- OpenCode native permission prompts remain available and continue to run inside tool execution.
- This plugin currently treats Abacus `ask` as plugin-side policy behavior (`allow-log` or `deny`) rather than triggering OpenCode interactive ask directly.
