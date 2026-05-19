import { describe, expect, it } from 'vitest'
import { createEngine, evaluate, loadPolicy, parsePolicyToml } from './index'
import type { Input } from './engine'

const sampleToml = `
[policy]
version = "test-v1"
permission_mode = "strict"
pattern_dialect = "glob"
pattern_case = "insensitive"
tool_match_mode = "tokenized_argv"

[default.tool.use]
"*" = "allow"
`

const baseInput: Input<'tool::use'> = {
  requestId: 'req-api',
  timestamp: new Date().toISOString(),
  actor: {
    id: 'actor-api',
    permissions: {},
  },
  action: 'tool::use',
  context: {
    type: 'tool',
    id: 'ctx-api',
    tool: 'bash',
  },
}

describe('public api', () => {
  it('parses policy TOML into normalized policy', () => {
    const policy = parsePolicyToml(sampleToml)
    expect(policy.meta.policyVersion).toBe('test-v1')
    expect(policy.rules.length).toBeGreaterThan(0)
  })

  it('loads policy from provided configToml', async () => {
    const policy = await loadPolicy({ configToml: sampleToml })
    expect(policy.meta.policyVersion).toBe('test-v1')
    expect(policy.meta.permissionModeEffect).toBe('deny')
  })

  it('creates engine with supplied policy', async () => {
    const policy = parsePolicyToml(sampleToml)
    const engine = await createEngine({ policy })
    expect(engine.policy).toBe(policy)
    expect(typeof engine.evaluate).toBe('function')
  })

  it('evaluate forwards runtime options', async () => {
    const policy = parsePolicyToml(sampleToml)
    await expect(
      evaluate(baseInput, {
        policy,
        runtime: {
          wasmPath: '/tmp/abacus-missing/policy.wasm',
          autoBuild: false,
        },
      }),
    ).rejects.toThrow(/Missing policy\.wasm/i)
  })
})
