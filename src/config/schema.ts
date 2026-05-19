export const SCOPES = ['fs', 'net', 'tool', 'skill', 'secret'] as const;
export type Scope = (typeof SCOPES)[number];

export const COMMON_VERBS = ['use', 'read', 'edit', 'create', 'delete', '*'] as const;
export type CommonVerb = (typeof COMMON_VERBS)[number];

export const NET_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head', '*'] as const;
export type NetVerb = (typeof NET_VERBS)[number];

export type Verb = CommonVerb | NetVerb;

export type Effect = 'deny' | 'ask' | 'allow';
export type PermissionMode = 'strict' | 'relax' | 'dangerous';

export type PatternDialect = 'glob';
export type PatternCase = 'insensitive' | 'sensitive';
export type ToolMatchMode = 'tokenized_argv';

export type SourceLayer =
  | 'override_exact'
  | 'override_wildcard'
  | 'agent_rule_exact'
  | 'agent_rule_wildcard'
  | 'agent_default'
  | 'global_default'
  | 'permission_mode';

export type RuleMatch = {
  pattern?: string;
  tool?: string;
  argv0?: string;
  argv?: string[];
  scheme?: string;
  host?: string;
  path?: string;
  port?: string;
};

export type NormalizedRule = {
  id: string;
  agent: string | '*';
  scope: Scope;
  verb: Verb;
  effect: Effect;
  reason?: string;
  match: RuleMatch;
  source: SourceLayer;
  priority: number;
  specificity: number;
};

export type NormalizedPolicyMeta = {
  version: number;
  permissionMode: PermissionMode;
  patternDialect: PatternDialect;
  patternCase: PatternCase;
  toolMatchMode: ToolMatchMode;
  permissionModeEffect: Effect;
};

export type NormalizedPolicy = {
  meta: NormalizedPolicyMeta;
  rules: NormalizedRule[];
};

export type RawPolicyConfig = {
  policy?: {
    version?: number;
    permission_mode?: string;
    pattern_dialect?: string;
    pattern_case?: string;
    tool_match_mode?: string;
  };
  default?: Record<string, unknown>;
  overrides?: unknown[];
  agents?: Record<string, unknown>;
};

export const SOURCE_PRIORITY: Record<SourceLayer, number> = {
  override_exact: 700,
  override_wildcard: 650,
  agent_rule_exact: 600,
  agent_rule_wildcard: 550,
  agent_default: 500,
  global_default: 400,
  permission_mode: 100,
};
