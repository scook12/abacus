import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, rmSync } from 'fs';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { normalize as normalizePath } from 'path';
import { loadPolicy as loadWasmPolicy, type LoadedPolicy } from '@open-policy-agent/opa-wasm';
import type { Decision, Input } from '../engine';
import type { NormalizedPolicy } from '../config/schema';

export type RegoDecision = {
  effect: Decision['effect'];
  source: string;
  reason?: string;
  rule_id?: string;
  policy_version?: string | number;
};

export type RegoRequest = {
  agent: string;
  scope: string;
  verb: string;
  match: Record<string, string | string[]>;
};

export type RegoEvalInput = {
  config: NormalizedPolicy;
  request: RegoRequest;
};

export type OpaCliOptions = {
  opaPath?: string;
  regoPath?: string;
  cwd?: string;
};

export type OpaWasmOptions = {
  opaPath?: string;
  regoPath?: string;
  regoPaths?: string[];
  wasmPath?: string;
  bundleDir?: string;
  cwd?: string;
  autoBuild?: boolean;
};

let cachedPolicyPath: string | undefined;
let cachedPolicyPromise: Promise<LoadedPolicy> | undefined;

function defaultPortForScheme(scheme: string): string {
  if (scheme === 'https' || scheme === 'wss') return '443';
  if (scheme === 'http' || scheme === 'ws') return '80';
  return '';
}

function normalizeScheme(scheme: string): string {
  return scheme.trim().toLowerCase().replace(/:$/, '');
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

function normalizeUrlPath(path: string): string {
  const raw = path.trim();
  if (raw === '') return '/';
  const withLeadingSlash = raw.startsWith('/') ? raw : `/${raw}`;
  const normalized = normalizePath(withLeadingSlash).replace(/\\/g, '/');
  return normalized === '' ? '/' : normalized;
}

function normalizeFsPath(path: string): string {
  const raw = path.trim();
  if (raw === '') return '';
  return normalizePath(raw).replace(/\\/g, '/');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function ensurePolicyWasm(options: OpaWasmOptions = {}): string {
  const cwd = options.cwd ?? process.cwd();
  const bundleDir = options.bundleDir ?? join(cwd, 'src', 'policy', 'bundle');
  const wasmPath = options.wasmPath ?? join(bundleDir, 'policy.wasm');

  if (existsSync(wasmPath)) {
    return wasmPath;
  }

  if (options.autoBuild === false) {
    throw new Error(`Missing policy.wasm at ${wasmPath}. Run the policy build first.`);
  }

  const opaPath = options.opaPath ?? 'opa';
  const regoSources =
    options.regoPaths ??
    (options.regoPath
      ? [options.regoPath]
      : [
          join(cwd, 'src', 'policy', 'main.rego'),
          join(cwd, 'src', 'policy', 'tool.rego'),
          join(cwd, 'src', 'policy', 'network.rego'),
          join(cwd, 'src', 'policy', 'filesystem.rego'),
          join(cwd, 'src', 'policy', 'secret.rego'),
          join(cwd, 'src', 'policy', 'skill.rego'),
          join(cwd, 'src', 'policy', 'escalate.rego'),
        ]);
  const tarPath = join(bundleDir, 'bundle.tar.gz');

  mkdirSync(bundleDir, { recursive: true });
  execFileSync(opaPath, ['build', '-t', 'wasm', '-e', 'abacus/decision', ...regoSources, '-o', tarPath], {
    cwd,
    encoding: 'utf8',
  });
  execFileSync('tar', ['-xzf', tarPath, '-C', bundleDir], { cwd, encoding: 'utf8' });
  rmSync(tarPath, { force: true });
  rmSync(join(bundleDir, 'data.json'), { force: true });
  rmSync(join(bundleDir, '.manifest'), { force: true });
  rmSync(join(bundleDir, 'src'), { recursive: true, force: true });

  if (!existsSync(wasmPath)) {
    throw new Error(`Failed to create policy.wasm at ${wasmPath}`);
  }
  return wasmPath;
}

async function getLoadedPolicy(options: OpaWasmOptions = {}): Promise<LoadedPolicy> {
  const wasmPath = ensurePolicyWasm(options);
  if (!cachedPolicyPromise || cachedPolicyPath !== wasmPath) {
    cachedPolicyPath = wasmPath;
    cachedPolicyPromise = readFile(wasmPath).then((bytes) => loadWasmPolicy(bytes));
  }
  return cachedPolicyPromise;
}

export function extractActionParts(action: Input['action']): { scope: string; verb: string } {
  const [scope, verb] = action.split('::');
  if (!scope || !verb) {
    throw new Error(`Invalid action format: ${action}`);
  }
  return { scope, verb };
}

export function toRequestMatch(input: Input): Record<string, string | string[]> {
  const ctx = input.context as Input['context'] & Record<string, unknown>;

  if (ctx.type === 'fs') {
    const path = normalizeFsPath(String(ctx.path));
    return { pattern: path };
  }

  if (ctx.type === 'tool') {
    return {
      pattern: String(ctx.tool),
      tool: String(ctx.tool),
      ...(typeof ctx.argv0 === 'string' ? { argv0: ctx.argv0 } : {}),
      ...(Array.isArray(ctx.argv) ? { argv: ctx.argv as string[] } : {}),
    };
  }

  if (ctx.type === 'skill') {
    const skill = String(ctx.skill);
    return { pattern: skill };
  }

  if (ctx.type === 'secret') {
    const secret = String(ctx.secret);
    return { pattern: secret };
  }

  if (ctx.type === 'net') {
    const fallbackUrl = String(ctx.url);
    let parsed: URL | undefined;
    try {
      parsed = new URL(fallbackUrl);
    } catch {
      parsed = undefined;
    }

    const schemeRaw = typeof ctx.scheme === 'string' ? ctx.scheme : parsed?.protocol.replace(':', '') ?? '';
    const scheme = normalizeScheme(schemeRaw);
    const hostRaw = typeof ctx.host === 'string' ? ctx.host : parsed?.hostname ?? '';
    const host = normalizeHost(hostRaw);
    const pathRaw = typeof ctx.path === 'string' ? ctx.path : parsed?.pathname ?? '/';
    const path = normalizeUrlPath(pathRaw);
    const explicitPort = typeof ctx.port === 'string' ? ctx.port.trim() : parsed?.port ?? '';
    const port = explicitPort === '' ? defaultPortForScheme(scheme) : explicitPort;

    return {
      pattern: fallbackUrl,
      host,
      path,
      scheme,
      port,
    };
  }

  return {};
}

export function buildRegoInput(policy: NormalizedPolicy, input: Input): RegoEvalInput {
  const action = extractActionParts(input.action);
  return {
    config: policy,
    request: {
      agent: input.agent ?? '',
      scope: action.scope,
      verb: action.verb,
      match: toRequestMatch(input),
    },
  };
}

export function readRegoDecisionFromEvalOutput(stdout: string): RegoDecision {
  const parsed = JSON.parse(stdout) as {
    result?: Array<{
      expressions?: Array<{ value?: unknown }>;
    }>;
  };

  const value = parsed.result?.[0]?.expressions?.[0]?.value;
  if (!value || typeof value !== 'object') {
    throw new Error('OPA returned no decision value');
  }
  return value as RegoDecision;
}

export function readRegoDecisionFromWasmResult(result: unknown): RegoDecision {
  if (!Array.isArray(result) || result.length === 0) {
    throw new Error('OPA Wasm returned no decision set');
  }

  const first = result[0];
  if (!isRecord(first)) {
    throw new Error('OPA Wasm returned invalid decision row');
  }

  const value = isRecord(first.result) ? first.result : first;
  if (!isRecord(value) || typeof value.effect !== 'string' || typeof value.source !== 'string') {
    throw new Error('OPA Wasm decision payload is missing effect/source');
  }

  return value as unknown as RegoDecision;
}

export function evaluateWithOpaCli(policy: NormalizedPolicy, input: Input, options: OpaCliOptions = {}): RegoDecision {
  const cwd = options.cwd ?? process.cwd();
  const regoPath = options.regoPath ?? join(cwd, 'src', 'policy', 'main.rego');
  const opaPath = options.opaPath ?? 'opa';
  const payload = JSON.stringify(buildRegoInput(policy, input));

  const stdout = execFileSync(
    opaPath,
    ['eval', '--format', 'json', '--stdin-input', '-d', regoPath, 'data.abacus.decision'],
    {
      encoding: 'utf8',
      input: payload,
      maxBuffer: 10 * 1024 * 1024,
      cwd,
    },
  );

  return readRegoDecisionFromEvalOutput(stdout);
}

export async function evaluateWithOpaWasm(
  policy: NormalizedPolicy,
  input: Input,
  options: OpaWasmOptions = {},
): Promise<RegoDecision> {
  const loaded = await getLoadedPolicy(options);
  const result = loaded.evaluate(buildRegoInput(policy, input));
  return readRegoDecisionFromWasmResult(result);
}

export function toEngineDecision(policy: NormalizedPolicy, decision: RegoDecision): Decision {
  const ruleId = decision.rule_id;
  return {
    policyVersion: String(decision.policy_version ?? policy.meta.policyVersion),
    effect: decision.effect,
    reasons: decision.reason ? [decision.reason] : [],
    source: decision.source,
    ...(ruleId !== undefined ? { ruleId } : {}),
  };
}
