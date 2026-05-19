import { describe, expect, it } from 'vitest';
import { normalizePolicy } from './normalize';
import type { RawPolicyConfig } from './schema';

function sampleConfig(): RawPolicyConfig {
  return {
    policy: {
      schema_version: 1,
      version: 'policy-v1',
      permission_mode: 'strict',
      pattern_dialect: 'glob',
      pattern_case: 'insensitive',
      tool_match_mode: 'tokenized_argv',
    },
    default: {
      fs: {
        read: {
          '*': 'allow',
        },
      },
      net: {
        default: 'ask',
        deny_methods: ['post'],
      },
    },
    overrides: [
      {
        scope: 'tool',
        verb: 'use',
        tool: 'webfetch',
        effect: 'deny',
        reason: 'block_webfetch',
      },
    ],
    agents: {
      build: {
        tool: {
          default: 'ask',
          rules: [
            {
              verb: 'use',
              tool: 'bash',
              argv0: 'git',
              effect: 'allow',
            },
          ],
        },
      },
    },
  };
}

describe('normalizePolicy', () => {
  it('computes meta defaults and permission-mode effect', () => {
    const normalized = normalizePolicy({ policy: { permission_mode: 'relax' } });

    expect(normalized.meta.schemaVersion).toBe(1);
    expect(normalized.meta.policyVersion).toBe(1);
    expect(normalized.meta.permissionMode).toBe('relax');
    expect(normalized.meta.permissionModeEffect).toBe('ask');
    expect(normalized.meta.patternDialect).toBe('glob');
    expect(normalized.meta.patternCase).toBe('insensitive');
    expect(normalized.meta.toolMatchMode).toBe('tokenized_argv');
  });

  it('preserves separate schema and policy versions', () => {
    const normalized = normalizePolicy(sampleConfig());

    expect(normalized.meta.schemaVersion).toBe(1);
    expect(normalized.meta.policyVersion).toBe('policy-v1');
  });

  it('creates rules from defaults, overrides, and agents', () => {
    const normalized = normalizePolicy(sampleConfig());

    expect(normalized.rules.length).toBeGreaterThan(0);

    const hasOverride = normalized.rules.some(
      (rule) =>
        rule.agent === '*' &&
        rule.scope === 'tool' &&
        rule.verb === 'use' &&
        rule.effect === 'deny' &&
        rule.match.tool === 'webfetch',
    );
    expect(hasOverride).toBe(true);

    const hasGlobalDefaultFsRead = normalized.rules.some(
      (rule) =>
        rule.source === 'global_default' &&
        rule.scope === 'fs' &&
        rule.verb === 'read' &&
        rule.match.pattern === '*' &&
        rule.effect === 'allow',
    );
    expect(hasGlobalDefaultFsRead).toBe(true);

    const hasAgentRule = normalized.rules.some(
      (rule) =>
        rule.agent === 'build' &&
        rule.scope === 'tool' &&
        rule.verb === 'use' &&
        rule.match.tool === 'bash' &&
        rule.match.argv0 === 'git' &&
        rule.effect === 'allow',
    );
    expect(hasAgentRule).toBe(true);
  });

  it('expands net deny_methods into explicit deny rules', () => {
    const normalized = normalizePolicy(sampleConfig());

    const denyPost = normalized.rules.find(
      (rule) =>
        rule.scope === 'net' &&
        rule.verb === 'post' &&
        rule.effect === 'deny' &&
        rule.reason === 'deny_method',
    );

    expect(denyPost).toBeDefined();
  });

  it('sorts rules by priority then specificity', () => {
    const normalized = normalizePolicy(sampleConfig());
    const priorities = normalized.rules.map((rule) => rule.priority);

    const isNonIncreasing = priorities.every((value, index) => {
      if (index === 0) return true;
      const previous = priorities[index - 1];
      if (previous === undefined) return true;
      return previous >= value;
    });

    expect(isNonIncreasing).toBe(true);
  });

  it('prefers exact over wildcard within same source layer', () => {
    const normalized = normalizePolicy({
      overrides: [
        {
          scope: 'tool',
          verb: 'use',
          tool: '*',
          effect: 'ask',
        },
        {
          scope: 'tool',
          verb: 'use',
          tool: 'webfetch',
          effect: 'allow',
        },
      ],
    });

    const wildcardIndex = normalized.rules.findIndex(
      (rule) => rule.scope === 'tool' && rule.verb === 'use' && rule.match.tool === '*',
    );
    const exactIndex = normalized.rules.findIndex(
      (rule) => rule.scope === 'tool' && rule.verb === 'use' && rule.match.tool === 'webfetch',
    );

    expect(exactIndex).toBeGreaterThanOrEqual(0);
    expect(wildcardIndex).toBeGreaterThanOrEqual(0);
    expect(exactIndex).toBeLessThan(wildcardIndex);
  });

  it('prefers agent-specific rules over global rules when source and specificity are equal', () => {
    const normalized = normalizePolicy({
      overrides: [
        {
          scope: 'tool',
          verb: 'use',
          tool: '*',
          effect: 'allow',
        },
        {
          agent: 'build',
          scope: 'tool',
          verb: 'use',
          tool: '*',
          effect: 'ask',
        },
      ],
    });

    const firstRule = normalized.rules[0];
    expect(firstRule).toBeDefined();
    expect(firstRule?.agent).toBe('build');
    expect(firstRule?.effect).toBe('ask');
  });

  it('prefers restrictive effects when source, specificity, and agent rank are equal', () => {
    const normalized = normalizePolicy({
      overrides: [
        {
          scope: 'tool',
          verb: 'use',
          tool: 'webfetch',
          effect: 'allow',
        },
        {
          scope: 'tool',
          verb: 'use',
          tool: 'webfetch',
          effect: 'deny',
        },
      ],
    });

    const firstRule = normalized.rules[0];
    expect(firstRule).toBeDefined();
    expect(firstRule?.effect).toBe('deny');
  });

  it('keeps override rules ahead of agent/default layers regardless of effect', () => {
    const normalized = normalizePolicy({
      default: {
        tool: {
          use: {
            '*': 'deny',
          },
        },
      },
      agents: {
        build: {
          tool: {
            default: 'deny',
            rules: [
              {
                verb: 'use',
                tool: '*',
                effect: 'deny',
              },
            ],
          },
        },
      },
      overrides: [
        {
          scope: 'tool',
          verb: 'use',
          tool: '*',
          effect: 'allow',
        },
      ],
    });

    const firstRule = normalized.rules[0];
    expect(firstRule).toBeDefined();
    expect(firstRule?.source).toMatch(/^override_/);
    expect(firstRule?.effect).toBe('allow');
  });

  it('throws for unsupported pattern dialect', () => {
    expect(() =>
      normalizePolicy({
        policy: {
          pattern_dialect: 'regex',
        },
      }),
    ).toThrow(/Unsupported pattern_dialect/);
  });

  it('throws for unsupported pattern case', () => {
    expect(() =>
      normalizePolicy({
        policy: {
          pattern_case: 'mixed',
        },
      }),
    ).toThrow(/Unsupported pattern_case/);
  });

  it('throws for unsupported tool match mode', () => {
    expect(() =>
      normalizePolicy({
        policy: {
          tool_match_mode: 'raw',
        },
      }),
    ).toThrow(/Unsupported tool_match_mode/);
  });

  it('ignores unknown scope keys in defaults and agents', () => {
    const normalized = normalizePolicy({
      default: {
        nope: {
          read: {
            '*': 'allow',
          },
        },
      },
      agents: {
        flow: {
          nope: {
            default: 'allow',
          },
        },
      },
    });

    expect(normalized.rules).toEqual([]);
  });

  it('throws when agents scope rules is not an array', () => {
    expect(() =>
      normalizePolicy({
        agents: {
          build: {
            tool: {
              rules: 'not-an-array' as unknown,
            },
          },
        },
      }),
    ).toThrow(/Expected array at agents\.build\.tool\.rules/);
  });
});
