import { describe, expect, it } from 'vitest';
import { normalizePolicy } from './normalize';
import { resolveDecision, resolveRule } from './resolve';
import type { RawPolicyConfig } from './schema';

describe('resolveDecision / resolveRule', () => {
  it('uses permission_mode when no rule matches', () => {
    const policy = normalizePolicy({ policy: { permission_mode: 'relax' } });
    const result = resolveDecision(policy, {
      agent: 'build',
      scope: 'tool',
      verb: 'use',
      match: { tool: 'bash', argv0: 'git', argv: ['status'] },
    });

    expect(result.effect).toBe('ask');
    expect(result.source).toBe('permission_mode');
    expect(result.rule).toBeUndefined();
  });

  it('selects override over agent and defaults', () => {
    const config: RawPolicyConfig = {
      policy: { permission_mode: 'strict' },
      default: {
        tool: {
          use: { '*': 'allow' },
        },
      },
      agents: {
        build: {
          tool: {
            rules: [
              {
                verb: 'use',
                tool: 'webfetch',
                effect: 'allow',
              },
            ],
          },
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
    };

    const policy = normalizePolicy(config);
    const result = resolveDecision(policy, {
      agent: 'build',
      scope: 'tool',
      verb: 'use',
      match: { tool: 'webfetch' },
    });

    expect(result.effect).toBe('deny');
    expect(result.source).toBe('override_exact');
    expect(result.reason).toBe('block_webfetch');
  });

  it('prefers exact over wildcard for matching candidates', () => {
    const policy = normalizePolicy({
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

    const rule = resolveRule(policy, {
      scope: 'tool',
      verb: 'use',
      match: { tool: 'webfetch' },
    });

    expect(rule).toBeDefined();
    expect(rule?.effect).toBe('allow');
    expect(rule?.match.tool).toBe('webfetch');
  });

  it('matches patterns case-insensitively by default', () => {
    const policy = normalizePolicy({
      overrides: [
        {
          scope: 'tool',
          verb: 'use',
          tool: 'WEBFETCH',
          effect: 'deny',
        },
      ],
    });

    const rule = resolveRule(policy, {
      scope: 'tool',
      verb: 'use',
      match: { tool: 'webfetch' },
    });

    expect(rule).toBeDefined();
    expect(rule?.effect).toBe('deny');
  });

  it('matches tokenized argv with ordered subsequence semantics', () => {
    const policy = normalizePolicy({
      overrides: [
        {
          scope: 'tool',
          verb: 'use',
          tool: 'bash',
          argv0: 'git',
          argv: ['push', '--force'],
          effect: 'deny',
        },
      ],
    });

    const deny = resolveDecision(policy, {
      scope: 'tool',
      verb: 'use',
      match: {
        tool: 'bash',
        argv0: 'git',
        argv: ['push', '--force', 'origin', 'main'],
      },
    });

    expect(deny.effect).toBe('deny');

    const fallback = resolveDecision(policy, {
      scope: 'tool',
      verb: 'use',
      match: {
        tool: 'bash',
        argv0: 'git',
        argv: ['push', 'origin', 'main'],
      },
    });

    expect(fallback.effect).toBe('deny');
    expect(fallback.source).toBe('permission_mode');
  });

  it('matches net host/path and method (verb) constraints', () => {
    const policy = normalizePolicy({
      policy: { permission_mode: 'strict' },
      overrides: [
        {
          scope: 'net',
          verb: 'get',
          host: '*.example.com',
          path: '/api/*',
          effect: 'allow',
        },
      ],
    });

    const allow = resolveDecision(policy, {
      scope: 'net',
      verb: 'get',
      match: { host: 'docs.example.com', path: '/api/v1/items' },
    });
    expect(allow.effect).toBe('allow');

    const deny = resolveDecision(policy, {
      scope: 'net',
      verb: 'post',
      match: { host: 'docs.example.com', path: '/api/v1/items' },
    });
    expect(deny.effect).toBe('deny');
    expect(deny.source).toBe('permission_mode');
  });

  it('applies agent-specific rule only when agent matches', () => {
    const policy = normalizePolicy({
      policy: { permission_mode: 'strict' },
      overrides: [
        {
          agent: 'build',
          scope: 'tool',
          verb: 'use',
          tool: 'bash',
          argv0: 'git',
          effect: 'allow',
        },
      ],
    });

    const buildAllow = resolveDecision(policy, {
      agent: 'build',
      scope: 'tool',
      verb: 'use',
      match: { tool: 'bash', argv0: 'git' },
    });
    expect(buildAllow.effect).toBe('allow');

    const researchDeny = resolveDecision(policy, {
      agent: 'research',
      scope: 'tool',
      verb: 'use',
      match: { tool: 'bash', argv0: 'git' },
    });
    expect(researchDeny.effect).toBe('deny');
    expect(researchDeny.source).toBe('permission_mode');
  });

  it('does not match when required match field is missing', () => {
    const policy = normalizePolicy({
      policy: { permission_mode: 'strict' },
      overrides: [
        {
          scope: 'net',
          verb: 'get',
          host: '*.example.com',
          effect: 'allow',
        },
      ],
    });

    const decision = resolveDecision(policy, {
      scope: 'net',
      verb: 'get',
      match: {},
    });

    expect(decision.effect).toBe('deny');
    expect(decision.source).toBe('permission_mode');
  });

  it('returns permission_mode when agent-specific rule has no agent in request', () => {
    const policy = normalizePolicy({
      policy: { permission_mode: 'strict' },
      overrides: [
        {
          agent: 'build',
          scope: 'tool',
          verb: 'use',
          tool: 'bash',
          effect: 'allow',
        },
      ],
    });

    const decision = resolveDecision(policy, {
      scope: 'tool',
      verb: 'use',
      match: { tool: 'bash' },
    });

    expect(decision.effect).toBe('deny');
    expect(decision.source).toBe('permission_mode');
  });
});
