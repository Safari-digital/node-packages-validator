<!-- markdownlint-disable-next-line -->
<p align="center">
    <img width="200" src="https://raw.githubusercontent.com/Safari-digital/.github/refs/heads/main/assets/logo-2025.svg" alt="Safari Digital Logo">
</p>

<p align="center">
    Supply-chain guard for Safari Digital JS/TS projects — audits npm & pnpm lockfiles
    against the <a href="https://github.com/DataDog/malicious-software-packages-dataset">DataDog malicious packages dataset</a>.
</p>

---

## Installation

```bash
pnpm add -D github:Safari-digital/node-packages-validator
```

No peer dependencies — the validator only uses the Node standard library.

## Usage

The package ships a `validate-package-lock` binary. Run it from the directory
holding the lockfile:

```bash
pnpm exec validate-package-lock
```

Wire it into `package.json` so it runs alongside the rest of the checks:

```json
{
    "scripts": {
        "validate": "validate-package-lock --pnpm"
    }
}
```

### Options

| Option        | Effect                                                                                                                                                    |
|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| _(none)_      | Validate the `package-lock.json` of the current directory.                                                                                                 |
| `--pnpm`      | Validate a `pnpm-lock.yaml` instead of a `package-lock.json`.                                                                                              |
| `--monorepo`  | Walk up to the repository root, then recursively validate every `package.json` and lockfile it finds — `node_modules`, `.git` and hidden folders excluded. |

`--pnpm` and `--monorepo` combine; in monorepo mode the lockfile flavour is
detected per file, so `--pnpm` then only tunes the remediation hint.

### Exit codes

| Code | Meaning                                                                        |
|------|--------------------------------------------------------------------------------|
| `0`  | Nothing matched the compromised list.                                          |
| `1`  | At least one compromised package was found, a file could not be read, or the dataset could not be fetched. |

The check fails closed: an unreachable dataset or an unparsable lockfile is
reported as a failure rather than silently passing. It needs network access to
`raw.githubusercontent.com` to fetch the dataset on every run.

## What gets checked

A package is reported when its **name** appears in the dataset and either the
dataset lists no version (every version is malicious) or the exact installed
version matches. Every version of a package present in the tree is checked, not
just the first one.

| Source              | Read from                                                                       |
|---------------------|---------------------------------------------------------------------------------|
| `package-lock.json` | `packages` (lockfileVersion 2 & 3) and the legacy `dependencies` tree (v1)      |
| `pnpm-lock.yaml`    | the top-level `packages:` section (pnpm v5 through v9 key formats)              |
| `package.json`      | `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`   |

`package.json` files are only scanned in `--monorepo` mode. Their versions are
ranges, so the range operator is stripped before comparison — treat those hits
as a weaker signal than a lockfile hit.

## Programmatic use

The class backing the CLI is exported, and every step is callable on its own:

```js
import PackageLock from 'node-packages-validator';

const errors = await PackageLock.validateAsync({ pnpm: true, monorepo: true });
if (errors > 0) process.exitCode = 1;
```

```js
import PackageLock from 'node-packages-validator';

const compromised = await PackageLock.getCompromisedPackagesAsync();
const index = PackageLock.indexFile('pnpm-lock.yaml');

PackageLock.checkIndex('MY-PROCESS', index, compromised);
```

`validateAsync` accepts `{ pnpm, monorepo, cwd }` and returns the number of
vulnerabilities found; each option falls back to the matching CLI flag. The
trace logger is reachable at `node-packages-validator/logger`.
