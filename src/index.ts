import { parse } from 'smol-toml'
import { homedir } from 'os'
import { join } from 'path'
import { constants } from 'fs'
import { access, readFile } from 'fs/promises'
import { type Input, type Decision } from './engine'
import { normalizePolicy } from './config/normalize'
import type { RawPolicyConfig, NormalizedPolicy } from './config/schema'
import { parseRawPolicyConfig } from './config/validate'
import { evaluateWithOpaWasm, toEngineDecision, type OpaWasmOptions } from './policy/runtime'

export type LoadPolicyOptions = {
  configPath?: string;
  configToml?: string;
};

export type EvaluateOptions = {
  policy?: NormalizedPolicy;
  configPath?: string;
  configToml?: string;
  runtime?: OpaWasmOptions;
};

export type CreateEngineOptions = {
  policy?: NormalizedPolicy;
  configPath?: string;
  configToml?: string;
  runtime?: OpaWasmOptions;
};

export type AbacusEngine = {
  policy: NormalizedPolicy;
  evaluate: (input: Input) => Promise<Decision>;
};

async function readTomlIfReadable(path: string): Promise<string | undefined> {
  try {
    await access(path, constants.R_OK)
    return readFile(path, { encoding: 'utf8' })
  } catch {
    return undefined
  }
}

async function resolveConfigToml(configPath?: string): Promise<string> {
  const paths: string[] = []
  if (configPath) {
    paths.push(configPath)
  }

  const envPath = process.env.ABACUS_CONFIG_PATH
  if (envPath && envPath !== configPath) {
    paths.push(envPath)
  }

  paths.push(join(process.cwd(), 'abacus.toml'))
  paths.push(join(homedir(), '.config', 'abacus', 'abacus.toml'))

  for (const path of paths) {
    const maybeToml = await readTomlIfReadable(path)
    if (maybeToml !== undefined) {
      return maybeToml
    }
  }

  throw new Error(`Unable to resolve abacus config. Checked: ${paths.join(', ')}`)
}

export function parsePolicyToml(configToml: string): NormalizedPolicy {
  const rawConfig = parse(configToml) as RawPolicyConfig
  const parsedConfig = parseRawPolicyConfig(rawConfig)
  return normalizePolicy(parsedConfig)
}

export async function loadPolicy(options: LoadPolicyOptions = {}): Promise<NormalizedPolicy> {
  if (options.configToml !== undefined) {
    return parsePolicyToml(options.configToml)
  }
  const configToml = await resolveConfigToml(options.configPath)
  return parsePolicyToml(configToml)
}

export async function createEngine(options: CreateEngineOptions = {}): Promise<AbacusEngine> {
  const loadOptions: LoadPolicyOptions = {}
  if (options.configPath !== undefined) {
    loadOptions.configPath = options.configPath
  }
  if (options.configToml !== undefined) {
    loadOptions.configToml = options.configToml
  }
  const policy = options.policy ?? (await loadPolicy(loadOptions))
  return {
    policy,
    evaluate: async (input: Input) => {
      const decision = await evaluateWithOpaWasm(policy, input, options.runtime)
      return toEngineDecision(policy, decision)
    },
  }
}

export async function evaluate(input: Input, options: EvaluateOptions = {}): Promise<Decision> {
  const loadOptions: LoadPolicyOptions = {}
  if (options.configPath !== undefined) {
    loadOptions.configPath = options.configPath
  }
  if (options.configToml !== undefined) {
    loadOptions.configToml = options.configToml
  }
  const policy = options.policy ?? (await loadPolicy(loadOptions))
  const decision = await evaluateWithOpaWasm(policy, input, options.runtime)
  return toEngineDecision(policy, decision)
}

export type { Action, Decision, Input } from './engine'
export type { RawPolicyConfig, NormalizedPolicy } from './config/schema'
export { parseRawPolicyConfig } from './config/validate'
export { normalizePolicy } from './config/normalize'

export default evaluate
