import { z } from 'zod';
import { COMMON_VERBS, NET_VERBS, SCOPES, type RawPolicyConfig, type Scope } from './schema';

const EFFECT_SCHEMA = z.enum(['deny', 'ask', 'allow']);

const RULE_MATCH_SCHEMA = z.object({
  pattern: z.string().optional(),
  tool: z.string().optional(),
  argv0: z.string().optional(),
  argv: z.array(z.string()).optional(),
  scheme: z.string().optional(),
  host: z.string().optional(),
  path: z.string().optional(),
  port: z.string().optional(),
});

const AGENT_RULE_SCHEMA = RULE_MATCH_SCHEMA.extend({
  verb: z.string().optional(),
  effect: EFFECT_SCHEMA,
  reason: z.string().optional(),
}).strict();

const OVERRIDE_RULE_SCHEMA = RULE_MATCH_SCHEMA.extend({
  agent: z.string().optional(),
  scope: z.string(),
  verb: z.string().optional(),
  effect: EFFECT_SCHEMA,
  reason: z.string().optional(),
}).strict();

const VERB_PATTERN_MAP_SCHEMA = z.record(z.string(), EFFECT_SCHEMA);

const SCOPE_BLOCK_SCHEMA = z.object({
  default: EFFECT_SCHEMA.optional(),
  deny_methods: z.array(z.string()).optional(),
  rules: z.array(AGENT_RULE_SCHEMA).optional(),
}).catchall(VERB_PATTERN_MAP_SCHEMA);

const POLICY_SCHEMA = z.object({
  schema_version: z.number().int().nonnegative().optional(),
  version: z.union([z.string(), z.number()]).optional(),
  permission_mode: z.enum(['strict', 'relax', 'dangerous']).optional(),
  pattern_dialect: z.literal('glob').optional(),
  pattern_case: z.enum(['insensitive', 'sensitive']).optional(),
  tool_match_mode: z.literal('tokenized_argv').optional(),
}).strict();

const RAW_POLICY_CONFIG_SCHEMA = z.object({
  policy: POLICY_SCHEMA.optional(),
  default: z.record(z.string(), SCOPE_BLOCK_SCHEMA).optional(),
  overrides: z.array(OVERRIDE_RULE_SCHEMA).optional(),
  agents: z.record(z.string(), z.record(z.string(), SCOPE_BLOCK_SCHEMA)).optional(),
}).strict();

function verbsForScope(scope: Scope): readonly string[] {
  return scope === 'net' ? NET_VERBS : COMMON_VERBS;
}

function isScope(scope: string): scope is Scope {
  return SCOPES.includes(scope as Scope);
}

function validateScopeBlock(
  scope: Scope,
  block: Record<string, unknown>,
  addIssue: (path: (string | number)[], message: string) => void,
  basePath: (string | number)[],
): void {
  const validVerbs = verbsForScope(scope);

  if (scope !== 'net' && block.deny_methods !== undefined) {
    addIssue([...basePath, 'deny_methods'], 'deny_methods is only valid for net scope');
  }

  for (const [key, value] of Object.entries(block)) {
    if (key === 'default' || key === 'deny_methods' || key === 'rules') {
      continue;
    }

    if (!validVerbs.includes(key)) {
      addIssue([...basePath, key], `Invalid verb '${key}' for scope '${scope}'`);
      continue;
    }

    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      addIssue([...basePath, key], 'Expected a pattern->effect map');
    }
  }

  if (Array.isArray(block.rules)) {
    block.rules.forEach((rule, idx) => {
      if (typeof rule !== 'object' || rule === null || Array.isArray(rule)) {
        addIssue([...basePath, 'rules', idx], 'Expected an object');
        return;
      }
      const maybeVerb = (rule as { verb?: unknown }).verb;
      if (typeof maybeVerb === 'string' && !validVerbs.includes(maybeVerb)) {
        addIssue([...basePath, 'rules', idx, 'verb'], `Invalid verb '${maybeVerb}' for scope '${scope}'`);
      }
    });
  }
}

export function parseRawPolicyConfig(raw: unknown): RawPolicyConfig {
  const parsed = RAW_POLICY_CONFIG_SCHEMA.superRefine((config, ctx) => {
    if (config.default) {
      for (const [scopeName, block] of Object.entries(config.default)) {
        if (!isScope(scopeName)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['default', scopeName],
            message: `Unknown scope '${scopeName}'`,
          });
          continue;
        }

        validateScopeBlock(
          scopeName,
          block,
          (path, message) => {
            ctx.addIssue({ code: z.ZodIssueCode.custom, path, message });
          },
          ['default', scopeName],
        );
      }
    }

    if (config.overrides) {
      config.overrides.forEach((override, idx) => {
        if (!isScope(override.scope)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['overrides', idx, 'scope'],
            message: `Unknown scope '${override.scope}'`,
          });
          return;
        }

        const validVerbs = verbsForScope(override.scope);
        const verb = override.verb ?? '*';
        if (!validVerbs.includes(verb)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['overrides', idx, 'verb'],
            message: `Invalid verb '${verb}' for scope '${override.scope}'`,
          });
        }
      });
    }

    if (config.agents) {
      for (const [agentName, scopes] of Object.entries(config.agents)) {
        for (const [scopeName, block] of Object.entries(scopes)) {
          if (!isScope(scopeName)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: ['agents', agentName, scopeName],
              message: `Unknown scope '${scopeName}'`,
            });
            continue;
          }

          validateScopeBlock(
            scopeName,
            block,
            (path, message) => {
              ctx.addIssue({ code: z.ZodIssueCode.custom, path, message });
            },
            ['agents', agentName, scopeName],
          );
        }
      }
    }
  }).parse(raw);

  return parsed as RawPolicyConfig;
}
