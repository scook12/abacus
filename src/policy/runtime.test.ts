import { describe, expect, it } from 'vitest';
import type { Input } from '../engine';
import type { NormalizedPolicy } from '../config/schema';
import {
  buildRegoInput,
  extractActionParts,
  readRegoDecisionFromEvalOutput,
  readRegoDecisionFromWasmResult,
  toEngineDecision,
  toRequestMatch,
} from './runtime';

const samplePolicy: NormalizedPolicy = {
  meta: {
    version: 1,
    permissionMode: 'strict',
    patternDialect: 'glob',
    patternCase: 'insensitive',
    toolMatchMode: 'tokenized_argv',
    permissionModeEffect: 'deny',
  },
  rules: [],
};

const baseInput = {
  requestId: 'req-1',
  timestamp: new Date().toISOString(),
  actor: {
    id: 'user-1',
    permissions: {},
  },
};

describe('policy runtime helpers', () => {
  it('extracts scope and verb from action', () => {
    const parts = extractActionParts('tool::use');
    expect(parts).toEqual({ scope: 'tool', verb: 'use' });
  });

  it('throws for invalid action format', () => {
    expect(() => extractActionParts('tool-use' as Input['action'])).toThrow(/Invalid action format/);
  });

  it('builds match payload for tool context with argv', () => {
    const input: Input<'tool::use'> = {
      ...baseInput,
      action: 'tool::use',
      context: {
        type: 'tool',
        id: 'ctx-1',
        tool: 'bash',
        argv0: 'git',
        argv: ['status'],
      },
    };

    expect(toRequestMatch(input)).toEqual({
      pattern: 'bash',
      tool: 'bash',
      argv0: 'git',
      argv: ['status'],
    });
  });

  it('builds net match payload from URL when host/path absent', () => {
    const input: Input<'net::get'> = {
      ...baseInput,
      action: 'net::get',
      context: {
        type: 'net',
        id: 'ctx-net',
        url: 'https://docs.example.com/api/v1/items',
      },
    };

    expect(toRequestMatch(input)).toEqual({
      pattern: 'https://docs.example.com/api/v1/items',
      host: 'docs.example.com',
      path: '/api/v1/items',
      scheme: 'https',
      port: '',
    });
  });

  it('builds full rego input envelope', () => {
    const input: Input<'skill::use'> = {
      ...baseInput,
      agent: 'flow',
      action: 'skill::use',
      context: {
        type: 'skill',
        id: 'ctx-skill',
        skill: 'research',
      },
    };

    const payload = buildRegoInput(samplePolicy, input);
    expect(payload.request).toEqual({
      agent: 'flow',
      scope: 'skill',
      verb: 'use',
      match: {
        pattern: 'research',
      },
    });
  });

  it('reads decision from opa eval json output', () => {
    const stdout = JSON.stringify({
      result: [
        {
          expressions: [
            {
              value: {
                effect: 'ask',
                source: 'override_exact',
                reason: 'human_review',
                policy_version: 2,
              },
            },
          ],
        },
      ],
    });

    const decision = readRegoDecisionFromEvalOutput(stdout);
    expect(decision.effect).toBe('ask');
    expect(decision.reason).toBe('human_review');
  });

  it('reads decision from opa wasm result set', () => {
    const resultSet = [
      {
        result: {
          effect: 'deny',
          source: 'override_exact',
          reason: 'blocked',
          policy_version: 5,
        },
      },
    ];

    const decision = readRegoDecisionFromWasmResult(resultSet);
    expect(decision.effect).toBe('deny');
    expect(decision.reason).toBe('blocked');
  });

  it('maps rego decision to engine decision', () => {
    const decision = toEngineDecision(samplePolicy, {
      effect: 'allow',
      source: 'override_exact',
      reason: 'allowed_rule',
      policy_version: 3,
    });

    expect(decision).toEqual({
      policyVersion: '3',
      effect: 'allow',
      reasons: ['allowed_rule'],
    });
  });
});
