import { parse } from 'smol-toml'
import { homedir } from 'os'
import { join } from 'path'
import { readFileSync, constants } from 'fs'
import { access } from 'fs/promises'
import { type Input, type Decision } from './engine'
import { normalizePolicy } from './config/normalize'
import type { NormalizedPolicy } from './config/schema'
import { parseRawPolicyConfig } from './config/validate'
import { evaluateWithOpaWasm, toEngineDecision } from './policy/runtime'

type Policy = NormalizedPolicy;

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

/// 
export default async function evaluate(t: Input): Promise<Decision> {
  const policy = await loadPolicy()
  const decision = await evaluateWithOpaWasm(policy, t)
  return toEngineDecision(policy, decision)
} 
