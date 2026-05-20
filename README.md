# ai-abacus workspace

Monorepo for Abacus core runtime and plugin packages.

## Packages

- `packages/abacus` - core ABAC policy runtime package published to npm as `@ai-abacus/core`
- `packages/plugin-opencode` - OpenCode plugin package published to npm as `@ai-abacus/plugin-opencode`

## Common commands

- `pnpm run build`
- `pnpm run test`
- `pnpm run typecheck`
- `pnpm run test:rego`

## Release

- Changesets config: `.changeset/config.json`
- Release checklist: `docs/release-checklist.md`
