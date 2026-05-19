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

testDescribe('evaluate conflict integration matrix', () => {
  const oldConfigPath = process.env.ABACUS_CONFIG_PATH;

  beforeAll(() => {
    const fixturePath = join(process.cwd(), 'src', 'config', 'fixtures', 'integration-conflicts.toml');
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
    requestId: 'req-conflicts',
    timestamp: new Date().toISOString(),
    actor: {
      id: 'actor-conflicts',
      permissions: {},
    },
  };

  const cases: Case[] = [
    {
      name: 'tool exact deny beats exact allow (effect tie-break)',
      input: {
        ...base,
        action: 'tool::use',
        context: { type: 'tool', id: 'c1', tool: 'bash' },
      },
      expected: {
        policyVersion: 'conflicts-2026-05',
        effect: 'deny',
        reasons: ['bash_deny'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'tool exact pattern deny beats wildcard allow',
      input: {
        ...base,
        action: 'tool::use',
        context: { type: 'tool', id: 'c2', tool: 'deploy-cli' },
      },
      expected: {
        policyVersion: 'conflicts-2026-05',
        effect: 'deny',
        reasons: ['deny_deploy_tools'],
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
        context: { type: 'tool', id: 'c3', tool: 'runner-1' },
      },
      expected: {
        policyVersion: 'conflicts-2026-05',
        effect: 'ask',
        reasons: ['build_tools_ask'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'override layer beats agent default/rule allow',
      input: {
        ...base,
        agent: 'build',
        action: 'tool::use',
        context: { type: 'tool', id: 'c4', tool: 'deploy-runner' },
      },
      expected: {
        policyVersion: 'conflicts-2026-05',
        effect: 'deny',
        reasons: ['deny_deploy_tools'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'net explicit http deny beats broader host/path allow',
      input: {
        ...base,
        action: 'net::get',
        context: { type: 'net', id: 'c5', url: 'http://api.corp.internal/api/v1/data' },
      },
      expected: {
        policyVersion: 'conflicts-2026-05',
        effect: 'deny',
        reasons: ['no_http'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'net host/path allow wins when scheme deny does not match',
      input: {
        ...base,
        action: 'net::get',
        context: { type: 'net', id: 'c6', url: 'https://api.corp.internal/api/v1/data' },
      },
      expected: {
        policyVersion: 'conflicts-2026-05',
        effect: 'allow',
        reasons: ['corp_api_allow'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'skill wildcard deny override beats agent skill allow',
      input: {
        ...base,
        agent: 'flow',
        action: 'skill::use',
        context: { type: 'skill', id: 'c7', skill: 'research' },
      },
      expected: {
        policyVersion: 'conflicts-2026-05',
        effect: 'deny',
        reasons: ['deny_all_skills'],
        source: 'override_wildcard',
        ruleId: 'any',
      },
    },
    {
      name: 'permission mode strict fallback when no rule matches',
      input: {
        ...base,
        action: 'fs::create',
        context: { type: 'fs', id: 'c8', path: '/tmp/new-file.txt' },
      },
      expected: {
        policyVersion: 'conflicts-2026-05',
        effect: 'deny',
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

  it('deterministic id tie-break is stable across evaluations', async () => {
    const input: Input<'secret::use'> = {
      ...base,
      action: 'secret::use',
      context: { type: 'secret', id: 'c9', secret: 'token' },
    };

    const first = await evaluate(input);
    const second = await evaluate(input);

    expect(first.policyVersion).toBe('conflicts-2026-05');
    expect(first.effect).toBe('ask');
    expect(first.source).toBe('override_exact');
    expect(first.ruleId).toEqual(expect.any(String));
    expect(first.reasons[0]).toMatch(/^secret_token_[ab]$/);

    expect(second).toEqual(first);
  });
});
