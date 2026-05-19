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

testDescribe('evaluate integration (toml -> normalize -> wasm)', () => {
  const oldConfigPath = process.env.ABACUS_CONFIG_PATH;

  beforeAll(() => {
    const fixturePath = join(process.cwd(), 'src', 'config', 'fixtures', 'integration.toml');
    process.env.ABACUS_CONFIG_PATH = fixturePath;
  });

  afterAll(() => {
    if (oldConfigPath === undefined) {
      delete process.env.ABACUS_CONFIG_PATH;
    } else {
      process.env.ABACUS_CONFIG_PATH = oldConfigPath;
    }
  });

  const baseInput = {
    requestId: 'req-int',
    timestamp: new Date().toISOString(),
    actor: {
      id: 'actor-1',
      permissions: {},
    },
  };

  it('denies blocked tool override', async () => {
    const input: Input<'tool::use'> = {
      ...baseInput,
      action: 'tool::use',
      context: {
        type: 'tool',
        id: 'ctx-tool-webfetch',
        tool: 'webfetch',
      },
    };

    const decision = await evaluate(input);
    expect(decision).toEqual({
      policyVersion: '2026-05-integration',
      effect: 'deny',
      reasons: ['block_webfetch'],
      source: 'override_exact',
      ruleId: expect.any(String),
    });
  });

  it('allows matching git tool rule', async () => {
    const input: Input<'tool::use'> = {
      ...baseInput,
      action: 'tool::use',
      context: {
        type: 'tool',
        id: 'ctx-tool-git',
        tool: 'bash',
        argv0: 'git',
      },
    };

    const decision = await evaluate(input);
    expect(decision).toEqual({
      policyVersion: '2026-05-integration',
      effect: 'allow',
      reasons: ['allow_git'],
      source: 'override_exact',
      ruleId: expect.any(String),
    });
  });

  it('allows matching net host/path + method rule', async () => {
    const input: Input<'net::get'> = {
      ...baseInput,
      action: 'net::get',
      context: {
        type: 'net',
        id: 'ctx-net-api',
        url: 'https://docs.example.com/api/v1/items',
      },
    };

    const decision = await evaluate(input);
    expect(decision).toEqual({
      policyVersion: '2026-05-integration',
      effect: 'allow',
      reasons: ['allow_example_api'],
      source: 'override_exact',
      ruleId: expect.any(String),
    });
  });

  it('falls back to permission mode when no rule matches', async () => {
    const input: Input<'skill::use'> = {
      ...baseInput,
      action: 'skill::use',
      context: {
        type: 'skill',
        id: 'ctx-skill-none',
        skill: 'unknown-skill',
      },
    };

    const decision = await evaluate(input);
    expect(decision).toEqual({
      policyVersion: '2026-05-integration',
      effect: 'ask',
      reasons: ['permission_mode_default'],
      source: 'permission_mode',
      ruleId: '',
    });
  });
});
