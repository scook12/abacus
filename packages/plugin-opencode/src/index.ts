import { createEngine, type Input } from '@ai-abacus/core'
import type { Plugin } from '@opencode-ai/plugin'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

type EnforcementMode = 'shadow' | 'enforce-deny' | 'enforce-full'
type AskBehavior = 'allow-log' | 'deny'

type Options = {
  mode?: EnforcementMode
  askBehavior?: AskBehavior
  configPath?: string
  configToml?: string
  policy?: string
  wasmPath?: string
  agentDefault?: string
  logDecisions?: boolean
}

type NormalizedOptions = {
  mode: EnforcementMode
  askBehavior: AskBehavior
  configPath: string | undefined
  configToml: string | undefined
  policy: string | undefined
  wasmPath: string | undefined
  agentDefault: string
  logDecisions: boolean
}

type AgentBySession = Map<string, string>

type DecisionLike = {
  effect: 'allow' | 'ask' | 'deny'
  source: string
  reasons: string[]
  ruleId?: string
}

type Candidate = {
  action: Input['action']
  context: Input['context']
}

const DEFAULT_CONFIG_PATHS = ['abacus.toml', '.opencode/abacus.toml']

function normalizeOptions(options: Options | undefined): NormalizedOptions {
  return {
    mode: options?.mode ?? 'enforce-full',
    askBehavior: options?.askBehavior ?? 'allow-log',
    configPath: options?.configPath,
    configToml: options?.configToml,
    policy: options?.policy,
    wasmPath: options?.wasmPath,
    agentDefault: options?.agentDefault ?? 'build',
    logDecisions: options?.logDecisions ?? true,
  }
}

function resolveConfigPath(inputPath: string | undefined, directory: string): string | undefined {
  if (inputPath !== undefined) {
    return resolve(directory, inputPath)
  }
  for (const rel of DEFAULT_CONFIG_PATHS) {
    const candidate = resolve(directory, rel)
    if (existsSync(candidate)) {
      return candidate
    }
  }
  return undefined
}

function mapToolContext(tool: string, args: Record<string, unknown>): Input['context'] {
  const requestId = `ctx:${tool}`

  const command = typeof args.command === 'string' ? args.command : ''
  const argv = command === '' ? undefined : command.trim().split(/\s+/).filter(Boolean)
  const argv0 = argv?.[0]
  return {
    type: 'tool',
    id: requestId,
    tool,
    ...(argv0 ? { argv0 } : {}),
    ...(argv && argv.length > 0 ? { argv } : {}),
  }
}

function resolveFsPath(rawPath: string, directory: string): string {
  return rawPath.startsWith('/') ? rawPath : resolve(directory, rawPath)
}

function extractPatchCandidates(patchText: string, directory: string): Candidate[] {
  const lines = patchText.split(/\r?\n/)
  const candidates: Candidate[] = []

  for (const line of lines) {
    if (line.startsWith('*** Add File: ')) {
      const filePath = resolveFsPath(line.slice('*** Add File: '.length).trim(), directory)
      candidates.push({
        action: 'fs::create',
        context: { type: 'fs', id: `ctx:patch:add:${filePath}`, path: filePath },
      })
      continue
    }

    if (line.startsWith('*** Update File: ')) {
      const filePath = resolveFsPath(line.slice('*** Update File: '.length).trim(), directory)
      candidates.push({
        action: 'fs::edit',
        context: { type: 'fs', id: `ctx:patch:update:${filePath}`, path: filePath },
      })
      continue
    }

    if (line.startsWith('*** Delete File: ')) {
      const filePath = resolveFsPath(line.slice('*** Delete File: '.length).trim(), directory)
      candidates.push({
        action: 'fs::delete',
        context: { type: 'fs', id: `ctx:patch:delete:${filePath}`, path: filePath },
      })
      continue
    }

    if (line.startsWith('*** Move to: ')) {
      const filePath = resolveFsPath(line.slice('*** Move to: '.length).trim(), directory)
      candidates.push({
        action: 'fs::create',
        context: { type: 'fs', id: `ctx:patch:move:${filePath}`, path: filePath },
      })
    }
  }

  return candidates
}

function buildCandidates(tool: string, args: Record<string, unknown>, directory: string): Candidate[] {
  const candidates: Candidate[] = [
    {
      action: 'tool::use',
      context: mapToolContext(tool, args),
    },
  ]

  if (tool === 'skill' && typeof args.name === 'string') {
    candidates.push({
      action: 'skill::use',
      context: {
        type: 'skill',
        id: `ctx:skill:${args.name}`,
        skill: args.name,
      },
    })
  }

  if (tool === 'webfetch' && typeof args.url === 'string') {
    candidates.push({
      action: 'net::get',
      context: {
        type: 'net',
        id: `ctx:net:${args.url}`,
        url: args.url,
      },
    })
  }

  if (tool === 'read' && typeof args.filePath === 'string') {
    const fsPath = resolveFsPath(args.filePath, directory)
    candidates.push({
      action: 'fs::read',
      context: {
        type: 'fs',
        id: `ctx:fs:read:${fsPath}`,
        path: fsPath,
      },
    })
  }

  if (tool === 'edit' && typeof args.filePath === 'string') {
    const fsPath = resolveFsPath(args.filePath, directory)
    candidates.push({
      action: 'fs::edit',
      context: {
        type: 'fs',
        id: `ctx:fs:edit:${fsPath}`,
        path: fsPath,
      },
    })
  }

  if (tool === 'write' && typeof args.filePath === 'string') {
    const fsPath = resolveFsPath(args.filePath, directory)
    const action: Input['action'] = existsSync(fsPath) ? 'fs::edit' : 'fs::create'
    candidates.push({
      action,
      context: {
        type: 'fs',
        id: `ctx:fs:write:${fsPath}`,
        path: fsPath,
      },
    })
  }

  if (tool === 'glob') {
    const fsPath = typeof args.path === 'string' ? resolveFsPath(args.path, directory) : directory
    candidates.push({
      action: 'fs::read',
      context: {
        type: 'fs',
        id: `ctx:fs:glob:${fsPath}`,
        path: fsPath,
      },
    })
  }

  if (tool === 'grep') {
    const fsPath = typeof args.path === 'string' ? resolveFsPath(args.path, directory) : directory
    candidates.push({
      action: 'fs::read',
      context: {
        type: 'fs',
        id: `ctx:fs:grep:${fsPath}`,
        path: fsPath,
      },
    })
  }

  if (tool === 'apply_patch' && typeof args.patchText === 'string') {
    candidates.push(...extractPatchCandidates(args.patchText, directory))
  }

  return candidates
}

function decisionRank(effect: DecisionLike['effect']): number {
  if (effect === 'deny') return 3
  if (effect === 'ask') return 2
  return 1
}

function summarizeDecision(decisions: DecisionLike[]): DecisionLike {
  const winner = [...decisions].sort((a, b) => decisionRank(b.effect) - decisionRank(a.effect))[0]
  if (!winner) {
    return {
      effect: 'allow',
      source: 'plugin_default',
      reasons: ['no_candidate'],
    }
  }
  return winner
}

function createBlockedError(tool: string, decision: DecisionLike): Error {
  const reasons = decision.reasons.length > 0 ? decision.reasons.join(', ') : 'no_reason'
  return new Error(
    `abacus denied ${tool} (source=${decision.source}, reasons=${reasons}${decision.ruleId ? `, ruleId=${decision.ruleId}` : ''})`,
  )
}

export const AbacusOpenCodePlugin: Plugin = async (ctx, rawOptions) => {
  const options = normalizeOptions(rawOptions as Options | undefined)
  const agentBySession: AgentBySession = new Map()
  const configPath = resolveConfigPath(options.configPath, ctx.directory)
  const policyFromInline = options.policy ?? options.configToml
  const engine = await createEngine({
    ...(policyFromInline ? { configToml: policyFromInline } : {}),
    ...(configPath ? { configPath } : {}),
    ...(options.wasmPath ? { runtime: { wasmPath: options.wasmPath, autoBuild: false } } : {}),
  })

  async function evaluate(tool: string, sessionID: string, args: Record<string, unknown>): Promise<DecisionLike> {
    const agent = agentBySession.get(sessionID) ?? options.agentDefault
    const candidates = buildCandidates(tool, args, ctx.directory)
    const results: DecisionLike[] = []

    for (const candidate of candidates) {
      const decision = await engine.evaluate({
        requestId: `opencode:${sessionID}:${tool}:${candidate.action}`,
        timestamp: new Date().toISOString(),
        agent,
        actor: {
          id: `opencode:${sessionID}`,
          permissions: {},
        },
        action: candidate.action,
        context: candidate.context,
      })
      results.push({
        effect: decision.effect,
        source: decision.source,
        reasons: decision.reasons,
        ...(decision.ruleId ? { ruleId: decision.ruleId } : {}),
      })
    }

    return summarizeDecision(results)
  }

  return {
    'chat.message': async (input) => {
      agentBySession.set(input.sessionID, input.agent ?? options.agentDefault)
    },
    'tool.execute.before': async (input, output) => {
      const args = (output.args ?? {}) as Record<string, unknown>
      const decision = await evaluate(input.tool, input.sessionID, args)

      if (options.logDecisions) {
        await ctx.client.app.log({
          body: {
            service: 'abacus-opencode-plugin',
            level: decision.effect === 'deny' ? 'warn' : 'info',
            message: 'abacus policy decision',
            extra: {
              tool: input.tool,
              sessionID: input.sessionID,
              effect: decision.effect,
              source: decision.source,
              reasons: decision.reasons,
              ruleId: decision.ruleId,
              mode: options.mode,
            },
          },
        })
      }

      if (options.mode === 'shadow') {
        return
      }

      if (decision.effect === 'deny') {
        throw createBlockedError(input.tool, decision)
      }

      if (decision.effect === 'ask' && options.mode === 'enforce-full' && options.askBehavior === 'deny') {
        throw createBlockedError(input.tool, {
          ...decision,
          reasons: decision.reasons.length > 0 ? decision.reasons : ['ask_behavior_deny'],
        })
      }
    },
    event: async ({ event }) => {
      if (!options.logDecisions) return
      if (event.type === 'session.deleted' || event.type === 'session.error') {
        const id = 'sessionID' in event.properties ? (event.properties.sessionID as string | undefined) : undefined
        if (id) {
          agentBySession.delete(id)
        }
      }
    },
  }
}

export default {
  id: '@ai-abacus/plugin-opencode',
  server: AbacusOpenCodePlugin,
}
