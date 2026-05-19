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
  input: Input<'tool::use'>;
  expected: {
    policyVersion: string;
    effect: 'deny' | 'ask' | 'allow';
    reasons: string[];
    source: string;
    ruleId: 'any' | 'empty';
  };
};

testDescribe('evaluate argv conflict integration matrix', () => {
  const oldConfigPath = process.env.ABACUS_CONFIG_PATH;

  beforeAll(() => {
    const fixturePath = join(process.cwd(), 'src', 'config', 'fixtures', 'integration-argv.toml');
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
    requestId: 'req-argv',
    timestamp: new Date().toISOString(),
    actor: {
      id: 'actor-argv',
      permissions: {},
    },
    action: 'tool::use' as const,
    context: {
      type: 'tool' as const,
      id: 'ctx-argv',
      tool: 'bash',
    },
  };

  const cases: Case[] = [
    {
      name: 'force-push subsequence deny beats git argv0 ask',
      input: {
        ...base,
        context: {
          ...base.context,
          id: 'a1',
          argv0: 'git',
          argv: ['push', '--force', 'origin', 'main'],
        },
      },
      expected: {
        policyVersion: 'argv-2026-05',
        effect: 'deny',
        reasons: ['deny_force_push'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'git status inherits argv0 ask by default',
      input: {
        ...base,
        context: {
          ...base.context,
          id: 'a2',
          argv0: 'git',
          argv: ['status'],
        },
      },
      expected: {
        policyVersion: 'argv-2026-05',
        effect: 'ask',
        reasons: ['ask_status'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'agent-specific status allow beats global status ask',
      input: {
        ...base,
        agent: 'build',
        context: {
          ...base.context,
          id: 'a3',
          argv0: 'git',
          argv: ['status'],
        },
      },
      expected: {
        policyVersion: 'argv-2026-05',
        effect: 'allow',
        reasons: ['build_allow_status'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'effect tie-break deny wins for identical checkout rules',
      input: {
        ...base,
        context: {
          ...base.context,
          id: 'a4',
          argv0: 'git',
          argv: ['checkout', 'feature/foo'],
        },
      },
      expected: {
        policyVersion: 'argv-2026-05',
        effect: 'deny',
        reasons: ['deny_checkout'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'case-insensitive argv matching works',
      input: {
        ...base,
        context: {
          ...base.context,
          id: 'a5',
          argv0: 'git',
          argv: ['version'],
        },
      },
      expected: {
        policyVersion: 'argv-2026-05',
        effect: 'allow',
        reasons: ['allow_version_case_insensitive'],
        source: 'override_exact',
        ruleId: 'any',
      },
    },
    {
      name: 'tool wildcard fallback allow when no argv0 rule matches',
      input: {
        ...base,
        context: {
          ...base.context,
          id: 'a6',
          argv0: 'python',
          argv: ['-c', 'print(1)'],
        },
      },
      expected: {
        policyVersion: 'argv-2026-05',
        effect: 'allow',
        reasons: ['allow_any_tool'],
        source: 'override_exact',
        ruleId: 'any',
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
