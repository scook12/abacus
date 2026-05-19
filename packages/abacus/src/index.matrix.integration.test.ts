import { execFileSync } from 'child_process';
import { join } from 'path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import evaluate from './index';
import type { Input } from './engine';

const hasOpa = (() => {
  try {
    execFileSync('opa', ['version'], { encoding: 'utf8' });
    return true;
  } catch {
    return false;
  }
})();

const testDescribe = hasOpa ? describe : describe.skip;

type Case = {
  name: string;
  input: Input;
  expected: {
    policyVersion: string;
    effect: 'deny' | 'ask' | 'allow';
    reasons: string[];
    source: string;
    ruleId: 'any' | 'empty';
  };
};

testDescribe('evaluate integration matrix (toml -> decision)', () => {
  const oldConfigPath = process.env.ABACUS_CONFIG_PATH;

  beforeAll(() => {
    const fixturePath = join(process.cwd(), 'src', 'config', 'fixtures', 'integration-matrix.toml');
    process.env.ABACUS_CONFIG_PATH = fixturePath;
  });

  afterAll(() => {
    if (oldConfigPath === undefined) {
      delete process.env.ABACUS_CONFIG_PATH;
    } else {
      process.env.ABACUS_CONFIG_PATH = oldConfigPath;
    }
  });

  const base = {
    requestId: 'req-matrix',
    timestamp: new Date().toISOString(),
    actor: {
      id: 'actor-matrix',
      permissions: {},
    },
  };

  const cases: Case[] = [
    {
      name: 'tool exact deny beats broader allows',
      input: {
        ...base,
        action: 'tool::use',
        context: { type: 'tool', id: 't1', tool: 'webfetch' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'deny',
        reasons: ['block_webfetch'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'agent-specific ask beats global allow when equally specific',
      input: {
        ...base,
        agent: 'build',
        action: 'tool::use',
        context: { type: 'tool', id: 't2', tool: 'todo-write' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'ask',
        reasons: ['ask_build_tools'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'effect tie-break picks deny over allow for same rule shape',
      input: {
        ...base,
        action: 'tool::use',
        context: { type: 'tool', id: 't3', tool: 'bash' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'deny',
        reasons: ['deny_bash'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'network rule matches normalized https host/path/port',
      input: {
        ...base,
        action: 'net::get',
        context: { type: 'net', id: 'n1', url: 'https://docs.example.com/api/v1/items' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'allow',
        reasons: ['allow_https_example_api'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'network http denied by scheme override',
      input: {
        ...base,
        action: 'net::get',
        context: { type: 'net', id: 'n2', url: 'http://docs.example.com/api/v1/items' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'deny',
        reasons: ['https_only'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'agent fs allow beats global fs ask/default behavior',
      input: {
        ...base,
        agent: 'build',
        action: 'fs::delete',
        context: { type: 'fs', id: 'f1', path: '/workspace/tmp/build.log' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'allow',
        reasons: ['matched_rule'],
        source: 'agent_rule_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'flow agent secret allow',
      input: {
        ...base,
        agent: 'flow',
        action: 'secret::use',
        context: { type: 'secret', id: 's1', secret: 'git' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'allow',
        reasons: ['matched_rule'],
        source: 'agent_rule_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'flow agent skill allow',
      input: {
        ...base,
        agent: 'flow',
        action: 'skill::use',
        context: { type: 'skill', id: 'k1', skill: 'research' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'allow',
        reasons: ['matched_rule'],
        source: 'agent_rule_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'permission mode fallback when nothing matches',
      input: {
        ...base,
        action: 'skill::use',
        context: { type: 'skill', id: 'k2', skill: 'unknown' },
      },
      expected: {
        policyVersion: 'matrix-2026-05',
        effect: 'ask',
        reasons: ['permission_mode_default'],
        source: 'permission_mode',
        ruleId: 'empty',
      },
    },
  ];

  for (const c of cases) {
    it(c.name, async () => {
      const decision = await evaluate(c.input);
      expect(decision.policyVersion).toBe(c.expected.policyVersion);
      expect(decision.effect).toBe(c.expected.effect);
      expect(decision.reasons).toEqual(c.expected.reasons);
      expect(decision.source).toBe(c.expected.source);
      if (c.expected.ruleId === 'any') {
        expect(decision.ruleId).toEqual(expect.any(String));
      } else {
        expect(decision.ruleId).toBe('');
      }
    });
  }
});
