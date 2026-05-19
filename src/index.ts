import { parse } from 'smol-toml'
import { homedir } from 'os'
import { join } from 'path'
import { readFileSync, constants } from 'fs'
import { access } from 'fs/promises'
import { execFileSync } from 'child_process'
import { type Input, type Decision } from './engine'
import { normalizePolicy } from './config/normalize'
import type { NormalizedPolicy } from './config/schema'
import { parseRawPolicyConfig } from './config/validate'

/// probably comes from policy/index.ts or we define it here...
type Policy = NormalizedPolicy;

type RegoDecision = {
  effect: Decision['effect'];
  source: string;
  reason?: string;
  rule_id?: string;
  policy_version?: string | number;
};

async function resolveConfig() {
  const readToml = (path: string) => readFileSync(path, { encoding: 'utf8' })
  try {
    const processOrLocalPath = process.env.ABACUS_CONFIG_PATH ?? join(__dirname, 'abacus.toml')
    await access(processOrLocalPath, constants.R_OK)
    return readToml(processOrLocalPath)
  } catch {
    const configPath = join(homedir(), '.config', 'abacus', 'abacus.toml')
    await access(configPath, constants.R_OK)
    return readToml(configPath)
  }
  
}

async function loadPolicy(): Promise<Policy> {
  const conf = await resolveConfig()
  const parsed = parseRawPolicyConfig(parse(conf))
  return normalizePolicy(parsed)
}

function extractActionParts(action: Input['action']): { scope: string; verb: string } {
  const [scope, verb] = action.split('::')
  if (!scope || !verb) {
    throw new Error(`Invalid action format: ${action}`)
  }
  return {
    scope,
    verb,
  }
}

function toRequestMatch(input: Input): Record<string, string | string[]> {
  const ctx = input.context as Input['context'] & Record<string, unknown>

  if (ctx.type === 'fs') {
    const path = String(ctx.path)
    return { pattern: path }
  }

  if (ctx.type === 'tool') {
    return {
      pattern: String(ctx.tool),
      tool: String(ctx.tool),
      ...(typeof ctx.argv0 === 'string' ? { argv0: ctx.argv0 } : {}),
      ...(Array.isArray(ctx.argv) ? { argv: ctx.argv as string[] } : {}),
    }
  }

  if (ctx.type === 'skill') {
    const skill = String(ctx.skill)
    return { pattern: skill }
  }

  if (ctx.type === 'secret') {
    const secret = String(ctx.secret)
    return { pattern: secret }
  }

  if (ctx.type === 'net') {
    const fallbackUrl = String(ctx.url)
    let parsed: URL | undefined
    try {
      parsed = new URL(fallbackUrl)
    } catch {
      parsed = undefined
    }

    const host = typeof ctx.host === 'string' ? ctx.host : parsed?.hostname ?? ''
    const path = typeof ctx.path === 'string' ? ctx.path : parsed?.pathname ?? ''
    const scheme = typeof ctx.scheme === 'string' ? ctx.scheme : parsed?.protocol.replace(':', '') ?? ''
    const port = typeof ctx.port === 'string' ? ctx.port : parsed?.port ?? ''

    return {
      pattern: fallbackUrl,
      host,
      path,
      scheme,
      port,
    }
  }

  return {}
}

function buildRegoInput(policy: Policy, input: Input): Record<string, unknown> {
  const action = extractActionParts(input.action)
  return {
    config: policy,
    request: {
      agent: input.agent ?? '',
      scope: action.scope,
      verb: action.verb,
      match: toRequestMatch(input),
    },
  }
}

function readRegoDecisionFromEvalOutput(stdout: string): RegoDecision {
  const parsed = JSON.parse(stdout) as {
    result?: Array<{
      expressions?: Array<{ value?: unknown }>;
    }>;
  }

  const value = parsed.result?.[0]?.expressions?.[0]?.value
  if (!value || typeof value !== 'object') {
    throw new Error('OPA returned no decision value')
  }
  return value as RegoDecision
}

function evaluateWithRego(policy: Policy, input: Input): RegoDecision {
  const regoPath = join(process.cwd(), 'src', 'policy', 'main.rego')
  const payload = JSON.stringify(buildRegoInput(policy, input))

  const stdout = execFileSync(
    'opa',
    ['eval', '--format', 'json', '--stdin-input', '-d', regoPath, 'data.abacus.decision'],
    {
      encoding: 'utf8',
      input: payload,
      maxBuffer: 10 * 1024 * 1024,
    },
  )

  return readRegoDecisionFromEvalOutput(stdout)
}

/// 
export default async function evaluate(t: Input): Promise<Decision> {
  const policy = await loadPolicy()
  const decision = evaluateWithRego(policy, t)
  return {
    policyVersion: String(decision.policy_version ?? policy.meta.version),
    effect: decision.effect,
    reasons: decision.reason ? [decision.reason] : [],
  };
} 
