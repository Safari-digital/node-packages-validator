## Installation

This library is designed to be used as submodule. To install it, run the following command:

```bash
git submodule add git@github.com:digital-net-org/node-packages-validator.git ./packages/node-packages-validator
```

## Usage

```bash
node ./packages/node-packages-validator/validate-package-lock.mjs [options]
```

### Options

- `--pnpm` — validate a `pnpm-lock.yaml` instead of a `package-lock.json`.
- `--monorepo` — recursively scan every `package.json` and lockfile of the
  repository (ignoring `node_modules`, `.git` and hidden directories) and
  validate them all in a single pass.
