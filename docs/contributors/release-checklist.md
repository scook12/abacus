# Release Checklist

This checklist is for publishing workspace packages with Changesets.

## Scope and Intent

- Packages are versioned independently.
- Only changed packages should be published.
- `packages/abacus` is the current publishable runtime package (`@ai-abacus/core`).

## 1) Pre-release validation

Run from repo root:

- `pnpm install`
- `pnpm run clean`
- `pnpm run build`
- `pnpm run test:rego`
- `pnpm run test`
- `pnpm run typecheck`

Optional package-level smoke test:

- `pnpm --filter @ai-abacus/core pack`

## 2) Create or verify changesets

- Add one changeset per user-visible package change:
  - `pnpm changeset`
- Confirm pending release plan:
  - `pnpm run release:status`

## 3) Versioning

- Apply version bumps and changelog updates:
  - `pnpm run release:version`
- Re-run verification after versioning:
  - `pnpm run build && pnpm run test && pnpm run typecheck`

## 4) Publish

- Ensure npm auth is available in environment.
- Publish changed packages:
  - `pnpm run release:publish`

## 5) Post-publish checks

- Verify package install in a clean temp project.
- Verify CJS and ESM import for `@ai-abacus/core`.
- Verify runtime evaluation path uses packaged Wasm without requiring `opa`.
