import {
  COMMON_VERBS,
  NET_VERBS,
  SCOPES,
  SOURCE_PRIORITY,
  type Effect,
  type NormalizedPolicy,
  type NormalizedRule,
  type PermissionMode,
  type RawPolicyConfig,
  type RuleMatch,
  type Scope,
  type SourceLayer,
  type Verb,
} from './schema';

type Dict = Record<string, unknown>;

const EFFECTS: Effect[] = ['deny', 'ask', 'allow'];
const PERMISSION_MODES: PermissionMode[] = ['strict', 'relax', 'dangerous'];
const PATTERN_CASES = ['insensitive', 'sensitive'] as const;

function isRecord(value: unknown): value is Dict {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertRecord(value: unknown, path: string): Dict {
  if (!isRecord(value)) {
    throw new Error(`Expected object at ${path}`);
  }
  return value;
}

function asString(value: unknown, path: string): string {
  if (typeof value !== 'string') {
    throw new Error(`Expected string at ${path}`);
  }
  return value;
}

function asOptionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function asOptionalStringArray(value: unknown, path: string): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new Error(`Expected string[] at ${path}`);
  }
  return value;
}

function buildMatch(fields: {
  pattern: string | undefined;
  tool: string | undefined;
  argv0: string | undefined;
  argv: string[] | undefined;
  scheme: string | undefined;
  host: string | undefined;
  path: string | undefined;
  port: string | undefined;
}): RuleMatch {
  const match: RuleMatch = {};
  if (fields.pattern !== undefined) match.pattern = fields.pattern;
  if (fields.tool !== undefined) match.tool = fields.tool;
  if (fields.argv0 !== undefined) match.argv0 = fields.argv0;
  if (fields.argv !== undefined) match.argv = fields.argv;
  if (fields.scheme !== undefined) match.scheme = fields.scheme;
  if (fields.host !== undefined) match.host = fields.host;
  if (fields.path !== undefined) match.path = fields.path;
  if (fields.port !== undefined) match.port = fields.port;
  return match;
}

function parseEffect(value: unknown, path: string): Effect {
  const effect = asString(value, path).toLowerCase() as Effect;
  if (!EFFECTS.includes(effect)) {
    throw new Error(`Invalid effect at ${path}: ${String(value)}`);
  }
  return effect;
}

function parsePermissionMode(value: unknown): PermissionMode {
  if (value === undefined) {
    return 'strict';
  }
  const mode = asString(value, 'policy.permission_mode').toLowerCase() as PermissionMode;
  if (!PERMISSION_MODES.includes(mode)) {
    throw new Error(`Invalid permission_mode: ${String(value)}`);
  }
  return mode;
}

function parseScope(value: unknown, path: string): Scope {
  const scope = asString(value, path).toLowerCase();
  if (!SCOPES.includes(scope as Scope)) {
    throw new Error(`Invalid scope at ${path}: ${String(value)}`);
  }
  return scope as Scope;
}

function verbsForScope(scope: Scope): readonly string[] {
  return scope === 'net' ? NET_VERBS : COMMON_VERBS;
}

function parseVerb(value: unknown, scope: Scope, path: string): Verb {
  const verb = asString(value, path).toLowerCase();
  if (!verbsForScope(scope).includes(verb)) {
    throw new Error(`Invalid verb '${verb}' for scope '${scope}' at ${path}`);
  }
  return verb as Verb;
}

function isWildcard(value?: string): boolean {
  if (!value) {
    return true;
  }
  return value.trim() === '*';
}

function countSpecificMatchFields(match: RuleMatch): number {
  let score = 0;
  if (match.pattern && !isWildcard(match.pattern)) score += 1;
  if (match.tool && !isWildcard(match.tool)) score += 1;
  if (match.argv0 && !isWildcard(match.argv0)) score += 1;
  if (match.argv && match.argv.length > 0 && match.argv.some((token) => !isWildcard(token))) score += 1;
  if (match.scheme && !isWildcard(match.scheme)) score += 1;
  if (match.host && !isWildcard(match.host)) score += 1;
  if (match.path && !isWildcard(match.path)) score += 1;
  if (match.port && !isWildcard(match.port)) score += 1;
  return score;
}

function inferRuleLayer(base: 'override' | 'agent_rule', verb: Verb, match: RuleMatch): SourceLayer {
  const hasSpecificVerb = verb !== '*';
  const hasSpecificFields = countSpecificMatchFields(match) > 0;
  const exact = hasSpecificVerb || hasSpecificFields;
  if (base === 'override') {
    return exact ? 'override_exact' : 'override_wildcard';
  }
  return exact ? 'agent_rule_exact' : 'agent_rule_wildcard';
}

function makeRuleId(rule: Omit<NormalizedRule, 'id'>): string {
  const stable = JSON.stringify({
    agent: rule.agent,
    scope: rule.scope,
    verb: rule.verb,
    effect: rule.effect,
    reason: rule.reason ?? '',
    match: rule.match,
    source: rule.source,
  });
  let hash = 0;
  for (let i = 0; i < stable.length; i += 1) {
    hash = ((hash << 5) - hash + stable.charCodeAt(i)) | 0;
  }
  return `r_${Math.abs(hash)}`;
}

function pushRule(rules: NormalizedRule[], draft: Omit<NormalizedRule, 'id' | 'priority' | 'specificity'>): void {
  const specificity = countSpecificMatchFields(draft.match) + (draft.verb === '*' ? 0 : 1);
  const rule: Omit<NormalizedRule, 'id'> = {
    ...draft,
    priority: SOURCE_PRIORITY[draft.source],
    specificity,
  };
  rules.push({ ...rule, id: makeRuleId(rule) });
}

function normalizePermissionMode(mode: PermissionMode): Effect {
  if (mode === 'dangerous') return 'allow';
  if (mode === 'relax') return 'ask';
  return 'deny';
}

function effectRank(effect: Effect): number {
  if (effect === 'deny') return 3;
  if (effect === 'ask') return 2;
  return 1;
}

function agentRank(agent: string | '*'): number {
  return agent === '*' ? 0 : 1;
}

function normalizeDefaultScopeVerbMaps(rules: NormalizedRule[], defaults: Dict): void {
  for (const [scopeKey, scopeValue] of Object.entries(defaults)) {
    if (!SCOPES.includes(scopeKey as Scope)) {
      continue;
    }
    const scope = scopeKey as Scope;
    const scopeObj = assertRecord(scopeValue, `default.${scope}`);

    if (scope === 'net') {
      const denyMethods = scopeObj.deny_methods;
      if (denyMethods !== undefined) {
        const methods = asOptionalStringArray(denyMethods, `default.${scope}.deny_methods`) ?? [];
        for (const method of methods) {
          const verb = parseVerb(method, scope, `default.${scope}.deny_methods[]`);
          pushRule(rules, {
            agent: '*',
            scope,
            verb,
            effect: 'deny',
            reason: 'deny_method',
            match: {},
            source: 'global_default',
          });
        }
      }
    }

    for (const [verbKey, verbValue] of Object.entries(scopeObj)) {
      if (verbKey === 'default' || verbKey === 'deny_methods' || verbKey === 'rules') {
        continue;
      }
      const verb = parseVerb(verbKey, scope, `default.${scope}.${verbKey}`);
      const verbTable = assertRecord(verbValue, `default.${scope}.${verb}`);
      for (const [pattern, effectRaw] of Object.entries(verbTable)) {
        pushRule(rules, {
          agent: '*',
          scope,
          verb,
          effect: parseEffect(effectRaw, `default.${scope}.${verb}.${pattern}`),
          match: { pattern },
          source: 'global_default',
        });
      }
    }
  }
}

function normalizeOverrideRules(rules: NormalizedRule[], overrideList: unknown[]): void {
  for (let i = 0; i < overrideList.length; i += 1) {
    const raw = assertRecord(overrideList[i], `overrides[${i}]`);
    const scope = parseScope(raw.scope, `overrides[${i}].scope`);
    const verb = parseVerb(raw.verb ?? '*', scope, `overrides[${i}].verb`);

    const match = buildMatch({
      pattern: asOptionalString(raw.pattern),
      tool: asOptionalString(raw.tool),
      argv0: asOptionalString(raw.argv0),
      argv: asOptionalStringArray(raw.argv, `overrides[${i}].argv`),
      scheme: asOptionalString(raw.scheme),
      host: asOptionalString(raw.host),
      path: asOptionalString(raw.path),
      port: asOptionalString(raw.port),
    });

    const reason = asOptionalString(raw.reason);

    pushRule(rules, {
      agent: asOptionalString(raw.agent) ?? '*',
      scope,
      verb,
      effect: parseEffect(raw.effect, `overrides[${i}].effect`),
      ...(reason !== undefined ? { reason } : {}),
      match,
      source: inferRuleLayer('override', verb, match),
    });
  }
}

function normalizeAgentRuleMaps(rules: NormalizedRule[], agentName: string, scope: Scope, scopeObj: Dict): void {
  for (const [verbKey, verbValue] of Object.entries(scopeObj)) {
    if (verbKey === 'default' || verbKey === 'deny_methods' || verbKey === 'rules') {
      continue;
    }

    const verb = parseVerb(verbKey, scope, `agents.${agentName}.${scope}.${verbKey}`);
    const verbTable = assertRecord(verbValue, `agents.${agentName}.${scope}.${verb}`);
    for (const [pattern, effectRaw] of Object.entries(verbTable)) {
      const match: RuleMatch = { pattern };
      pushRule(rules, {
        agent: agentName,
        scope,
        verb,
        effect: parseEffect(effectRaw, `agents.${agentName}.${scope}.${verb}.${pattern}`),
        match,
        source: inferRuleLayer('agent_rule', verb, match),
      });
    }
  }
}

function normalizeAgentDefault(rules: NormalizedRule[], agentName: string, scope: Scope, scopeObj: Dict): void {
  if (scopeObj.default !== undefined) {
    pushRule(rules, {
      agent: agentName,
      scope,
      verb: '*',
      effect: parseEffect(scopeObj.default, `agents.${agentName}.${scope}.default`),
      match: {},
      source: 'agent_default',
    });
  }
}

function normalizeAgentDenyMethods(rules: NormalizedRule[], agentName: string, scope: Scope, scopeObj: Dict): void {
  if (scope !== 'net' || scopeObj.deny_methods === undefined) {
    return;
  }
  const methods = asOptionalStringArray(scopeObj.deny_methods, `agents.${agentName}.net.deny_methods`) ?? [];
  for (const method of methods) {
    const verb = parseVerb(method, scope, `agents.${agentName}.net.deny_methods[]`);
    pushRule(rules, {
      agent: agentName,
      scope,
      verb,
      effect: 'deny',
      reason: 'deny_method',
      match: {},
      source: 'agent_rule_exact',
    });
  }
}

function normalizeAgentRulesArray(rules: NormalizedRule[], agentName: string, scope: Scope, scopeObj: Dict): void {
  if (scopeObj.rules === undefined) {
    return;
  }
  if (!Array.isArray(scopeObj.rules)) {
    throw new Error(`Expected array at agents.${agentName}.${scope}.rules`);
  }

  for (let i = 0; i < scopeObj.rules.length; i += 1) {
    const raw = assertRecord(scopeObj.rules[i], `agents.${agentName}.${scope}.rules[${i}]`);
    const verb = parseVerb(raw.verb ?? '*', scope, `agents.${agentName}.${scope}.rules[${i}].verb`);
    const match = buildMatch({
      pattern: asOptionalString(raw.pattern),
      tool: asOptionalString(raw.tool),
      argv0: asOptionalString(raw.argv0),
      argv: asOptionalStringArray(raw.argv, `agents.${agentName}.${scope}.rules[${i}].argv`),
      scheme: asOptionalString(raw.scheme),
      host: asOptionalString(raw.host),
      path: asOptionalString(raw.path),
      port: asOptionalString(raw.port),
    });

    const reason = asOptionalString(raw.reason);

    pushRule(rules, {
      agent: agentName,
      scope,
      verb,
      effect: parseEffect(raw.effect, `agents.${agentName}.${scope}.rules[${i}].effect`),
      ...(reason !== undefined ? { reason } : {}),
      match,
      source: inferRuleLayer('agent_rule', verb, match),
    });
  }
}

function normalizeAgentSections(rules: NormalizedRule[], agents: Dict): void {
  for (const [agentName, rawAgent] of Object.entries(agents)) {
    const agentObj = assertRecord(rawAgent, `agents.${agentName}`);
    for (const [scopeKey, rawScope] of Object.entries(agentObj)) {
      if (!SCOPES.includes(scopeKey as Scope)) {
        continue;
      }
      const scope = scopeKey as Scope;
      const scopeObj = assertRecord(rawScope, `agents.${agentName}.${scope}`);

      normalizeAgentDefault(rules, agentName, scope, scopeObj);
      normalizeAgentDenyMethods(rules, agentName, scope, scopeObj);
      normalizeAgentRuleMaps(rules, agentName, scope, scopeObj);
      normalizeAgentRulesArray(rules, agentName, scope, scopeObj);
    }
  }
}

export function normalizePolicy(rawConfig: RawPolicyConfig): NormalizedPolicy {
  const policy = assertRecord(rawConfig.policy ?? {}, 'policy');
  const version = typeof policy.version === 'number' ? policy.version : 1;
  const permissionMode = parsePermissionMode(policy.permission_mode);

  const patternDialect = (policy.pattern_dialect ?? 'glob') as string;
  if (patternDialect !== 'glob') {
    throw new Error(`Unsupported pattern_dialect: ${patternDialect}`);
  }

  const patternCase = (policy.pattern_case ?? 'insensitive') as string;
  if (!(PATTERN_CASES as readonly string[]).includes(patternCase)) {
    throw new Error(`Unsupported pattern_case: ${patternCase}`);
  }

  const toolMatchMode = (policy.tool_match_mode ?? 'tokenized_argv') as string;
  if (toolMatchMode !== 'tokenized_argv') {
    throw new Error(`Unsupported tool_match_mode: ${toolMatchMode}`);
  }

  const rules: NormalizedRule[] = [];
  normalizeDefaultScopeVerbMaps(rules, assertRecord(rawConfig.default ?? {}, 'default'));
  normalizeOverrideRules(rules, Array.isArray(rawConfig.overrides) ? rawConfig.overrides : []);
  normalizeAgentSections(rules, assertRecord(rawConfig.agents ?? {}, 'agents'));

  rules.sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority;
    if (b.specificity !== a.specificity) return b.specificity - a.specificity;
    if (agentRank(b.agent) !== agentRank(a.agent)) return agentRank(b.agent) - agentRank(a.agent);
    if (effectRank(b.effect) !== effectRank(a.effect)) return effectRank(b.effect) - effectRank(a.effect);
    return a.id.localeCompare(b.id);
  });

  return {
    meta: {
      version,
      permissionMode,
      patternDialect: 'glob',
      patternCase: patternCase as 'insensitive' | 'sensitive',
      toolMatchMode: 'tokenized_argv',
      permissionModeEffect: normalizePermissionMode(permissionMode),
    },
    rules,
  };
}
