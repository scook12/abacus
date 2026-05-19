import { execFileSync } from 'child_process';
import { join } from 'path';
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
    const path = String(ctx.path);
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

    const host = typeof ctx.host === 'string' ? ctx.host : parsed?.hostname ?? '';
    const path = typeof ctx.path === 'string' ? ctx.path : parsed?.pathname ?? '';
    const scheme = typeof ctx.scheme === 'string' ? ctx.scheme : parsed?.protocol.replace(':', '') ?? '';
    const port = typeof ctx.port === 'string' ? ctx.port : parsed?.port ?? '';

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

export function toEngineDecision(policy: NormalizedPolicy, decision: RegoDecision): Decision {
  return {
    policyVersion: String(decision.policy_version ?? policy.meta.version),
    effect: decision.effect,
    reasons: decision.reason ? [decision.reason] : [],
  };
}
