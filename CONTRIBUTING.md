# Contributing

Thanks for helping improve JS Secret Hunter. Keep changes focused, avoid including real credentials or customer traffic in issues and fixtures, and use synthetic examples in tests.

## Local setup

Use Node.js 22+ and the pnpm version declared in `package.json`.

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test:coverage
pnpm lint
pnpm knip
pnpm audit --audit-level high
pnpm build
```

All commands must pass before a pull request is ready. New behavior and bug fixes should include focused tests. Do not weaken coverage thresholds or security controls without explaining the tradeoff.

## Detector rules

Keep rules narrow, document their expected signal, include positive and negative fixtures, and avoid storing raw matched secrets. New rules must preserve preview redaction and stable fingerprint behavior.

## Pull requests

- Describe the problem, user impact, and verification performed.
- Call out database migrations, network behavior, credential handling, or changed defaults.
- Include screenshots for visible UI changes when practical.
- Update `CHANGELOG.md` for user-visible changes.

By contributing, you agree that your work is licensed under the repository's MIT license.
