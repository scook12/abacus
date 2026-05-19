import type {
  Effect,
  NormalizedPolicy,
  NormalizedRule,
  RuleMatch,
  Scope,
  SourceLayer,
  Verb,
} from './schema';

export type ResolveInput = {
  agent?: string;
  scope: Scope;
  verb: Verb;
  match?: RuleMatch;
};

export type ResolveResult = {
  effect: Effect;
  source: SourceLayer;
  reason?: string;
  ruleId?: string;
  rule?: NormalizedRule;
};

function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`);
}

function matchGlob(pattern: string, value: string, caseSensitive: boolean): boolean {
  const normalizedPattern = caseSensitive ? pattern : pattern.toLowerCase();
  const normalizedValue = caseSensitive ? value : value.toLowerCase();
  return globToRegex(normalizedPattern).test(normalizedValue);
}

function matchField(
  ruleValue: string | undefined,
  inputValue: string | undefined,
  caseSensitive: boolean,
): boolean {
  if (ruleValue === undefined) {
    return true;
  }
  if (inputValue === undefined) {
    return false;
  }
  return matchGlob(ruleValue, inputValue, caseSensitive);
}

function matchArgvSubsequence(
  ruleArgv: string[] | undefined,
  inputArgv: string[] | undefined,
  caseSensitive: boolean,
): boolean {
  if (ruleArgv === undefined) {
    return true;
  }
  if (inputArgv === undefined) {
    return false;
  }
  if (ruleArgv.length === 0) {
    return true;
  }

  let seekIndex = 0;
  for (const token of inputArgv) {
    const expected = ruleArgv[seekIndex];
    if (expected === undefined) {
      return true;
    }
    if (matchGlob(expected, token, caseSensitive)) {
      seekIndex += 1;
      if (seekIndex >= ruleArgv.length) {
        return true;
      }
    }
  }
  return false;
}

function matchesRule(rule: NormalizedRule, input: ResolveInput, caseSensitive: boolean): boolean {
  if (rule.scope !== input.scope) {
    return false;
  }

  if (rule.verb !== '*' && rule.verb !== input.verb) {
    return false;
  }

  const requestedAgent = input.agent;
  if (rule.agent !== '*') {
    if (requestedAgent === undefined) {
      return false;
    }
    if (rule.agent !== requestedAgent) {
      return false;
    }
  }

  const match = input.match ?? {};

  if (!matchField(rule.match.pattern, match.pattern, caseSensitive)) return false;
  if (!matchField(rule.match.tool, match.tool, caseSensitive)) return false;
  if (!matchField(rule.match.argv0, match.argv0, caseSensitive)) return false;
  if (!matchArgvSubsequence(rule.match.argv, match.argv, caseSensitive)) return false;
  if (!matchField(rule.match.scheme, match.scheme, caseSensitive)) return false;
  if (!matchField(rule.match.host, match.host, caseSensitive)) return false;
  if (!matchField(rule.match.path, match.path, caseSensitive)) return false;
  if (!matchField(rule.match.port, match.port, caseSensitive)) return false;

  return true;
}

export function resolveRule(policy: NormalizedPolicy, input: ResolveInput): NormalizedRule | undefined {
  const caseSensitive = policy.meta.patternCase === 'sensitive';
  for (const rule of policy.rules) {
    if (matchesRule(rule, input, caseSensitive)) {
      return rule;
    }
  }
  return undefined;
}

export function resolveDecision(policy: NormalizedPolicy, input: ResolveInput): ResolveResult {
  const matched = resolveRule(policy, input);
  if (!matched) {
    return {
      effect: policy.meta.permissionModeEffect,
      source: 'permission_mode',
      reason: 'permission_mode_default',
    };
  }

  const reason = matched.reason;
  return {
    effect: matched.effect,
    source: matched.source,
    ...(reason !== undefined ? { reason } : {}),
    ruleId: matched.id,
    rule: matched,
  };
}
