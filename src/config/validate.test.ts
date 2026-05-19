import { describe, expect, it } from 'vitest';
import { parseRawPolicyConfig } from './validate';

describe('parseRawPolicyConfig', () => {
  it('accepts an empty config', () => {
    const parsed = parseRawPolicyConfig({});
    expect(parsed).toEqual({});
  });

  it('rejects unknown top-level keys', () => {
    expect(() => parseRawPolicyConfig({ nope: true })).toThrow(/unrecognized key/i);
  });

  it('rejects unknown scopes in default', () => {
    expect(() => parseRawPolicyConfig({ default: { nope: {} } })).toThrow(/Unknown scope 'nope'/);
  });

  it('rejects invalid verb for scope in overrides', () => {
    expect(() =>
      parseRawPolicyConfig({
        overrides: [{ scope: 'net', verb: 'use', effect: 'deny' }],
      }),
    ).toThrow(/Invalid verb 'use' for scope 'net'/);
  });

  it('rejects unknown scope in overrides', () => {
    expect(() =>
      parseRawPolicyConfig({
        overrides: [{ scope: 'nope', verb: '*', effect: 'deny' }],
      }),
    ).toThrow(/Unknown scope 'nope'/);
  });

  it('rejects deny_methods on non-net scopes', () => {
    expect(() =>
      parseRawPolicyConfig({
        agents: {
          build: {
            fs: {
              deny_methods: ['delete'],
            },
          },
        },
      }),
    ).toThrow(/deny_methods is only valid for net scope/);
  });

  it('rejects unknown scope under agents', () => {
    expect(() =>
      parseRawPolicyConfig({
        agents: {
          flow: {
            nope: {
              default: 'deny',
            },
          },
        },
      }),
    ).toThrow(/Unknown scope 'nope'/);
  });

  it('accepts schema_version and user policy version', () => {
    const parsed = parseRawPolicyConfig({
      policy: {
        schema_version: 2,
        version: 'user-policy-2026-05',
      },
    });

    expect(parsed.policy?.schema_version).toBe(2);
    expect(parsed.policy?.version).toBe('user-policy-2026-05');
  });
});
