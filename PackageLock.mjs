import fs from 'fs';
import path from 'path';
import Logger from './Logger.mjs';

const NPM_LOCK_FILE = 'package-lock.json';
const PNPM_LOCK_FILE = 'pnpm-lock.yaml';
const PACKAGE_FILE = 'package.json';

const NODE_MODULES = 'node_modules/';
const PROCESS_ID = 'PACKAGE-LOCK-VALIDATION';

/**
 * Curated list of known-malicious npm packages, maintained by DataDog.
 * See https://github.com/DataDog/malicious-software-packages-dataset for further information.
 */
const COMPROMISED_PACKAGES_SOURCE =
    'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/refs/heads/main/samples/npm/manifest.json';

const VALIDATED_FILES = [NPM_LOCK_FILE, PNPM_LOCK_FILE, PACKAGE_FILE];
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git']);

export default class PackageLock {
    static usePnpm = process.argv.includes('--pnpm');
    static monorepo = process.argv.includes('--monorepo');

    /**
     * Get the lockfile name based on the active package manager
     * @param {boolean} usePnpm Whether pnpm is the active package manager
     * @returns {string}
     */
    static getLockFileName = (usePnpm = this.usePnpm) => (usePnpm ? PNPM_LOCK_FILE : NPM_LOCK_FILE);

    /**
     * Get the content of a package-lock.json
     * @param {string} filePath Path to the package-lock.json
     * @returns {Object}
     */
    static getPackageLock = (filePath = NPM_LOCK_FILE) => JSON.parse(fs.readFileSync(filePath, 'utf8'));

    /**
     * Get the list of infected packages. A `null` value means every version of
     * the package is compromised, an array lists the compromised versions.
     * @returns {Promise<{[string]: null | Array<string> }>}
     */
    static async getCompromisedPackagesAsync() {
        const response = await fetch(COMPROMISED_PACKAGES_SOURCE);
        if (!response.ok) {
            throw new Error(`${response.status} ${response.statusText}`);
        }
        return await response.json();
    }

    /**
     * Find the root of the repository by walking up from a starting directory
     * until a `.git` entry is found. Falls back to the starting directory.
     * @param {string} startDir Directory to start the lookup from
     * @returns {string} Absolute path to the repository root
     */
    static findRepositoryRoot(startDir = process.cwd()) {
        let directory = path.resolve(startDir);

        while (true) {
            if (fs.existsSync(path.join(directory, '.git'))) return directory;
            const parent = path.dirname(directory);
            if (parent === directory) return path.resolve(startDir);
            directory = parent;
        }
    }

    /**
     * Recursively find every package.json and lockfile in a directory,
     * ignoring node_modules, the .git folder and hidden directories.
     * @param {string} directory Directory to scan from
     * @returns {Array<string>} List of file paths
     */
    static findValidatedFiles(directory = '.') {
        const results = [];

        const walk = dir => {
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                const fullPath = path.join(dir, entry.name);

                if (entry.isDirectory()) {
                    if (IGNORED_DIRECTORIES.has(entry.name) || entry.name.startsWith('.')) continue;
                    walk(fullPath);
                } else if (entry.isFile() && VALIDATED_FILES.includes(entry.name)) {
                    results.push(fullPath);
                }
            }
        };

        walk(directory);
        return results;
    }

    /**
     * Register a resolved package in an index. A single name can hold several
     * versions — every one of them has to be checked, so they are all kept.
     * @param {Object} index Index to mutate
     * @param {string} name Package name
     * @param {string} version Exact version
     * @param {string} resolved Tarball URL (optional)
     * @returns {{version: string, resolved: string} | null} The stored entry
     */
    static addEntry(index, name, version, resolved = '') {
        if (!name || !version) return null;

        const entries = (index[name] ??= []);
        const existing = entries.find(entry => entry.version === version);

        if (existing) {
            if (!existing.resolved && resolved) existing.resolved = resolved;
            return existing;
        }

        const entry = { version: String(version), resolved: resolved ?? '' };
        entries.push(entry);
        return entry;
    }

    /**
     * Extract a package name from a npm lockfile location.
     * `node_modules/a/node_modules/@scope/b` resolves to `@scope/b`.
     * @param {string} location Key of a `packages` entry
     * @returns {string | null} Package name, or null when the entry is not installed
     */
    static getPackageNameFromLocation(location) {
        const index = location.lastIndexOf(NODE_MODULES);
        return index === -1 ? null : location.slice(index + NODE_MODULES.length);
    }

    /**
     * Create an index of all packages in a npm package-lock.json.
     * Handles both the `packages` map (lockfileVersion >= 2, keyed by install
     * path) and the legacy `dependencies` tree (lockfileVersion 1, keyed by name).
     * @param {string} filePath Path to the package-lock.json
     * @returns {Object}
     */
    static indexNpmPackages(filePath = NPM_LOCK_FILE) {
        const lock = this.getPackageLock(filePath);
        const index = {};

        for (const [location, data] of Object.entries(lock.packages ?? {})) {
            if (!data || data.link) continue;

            // Workspace sources and the root project are not installed packages
            const installed = this.getPackageNameFromLocation(location);
            if (!installed) continue;

            // `name` is set when the folder differs from the package, i.e. aliases
            this.addEntry(index, data.name ?? installed, data.version, data.resolved ?? '');
        }

        const scan = dependencies => {
            for (const [name, data] of Object.entries(dependencies ?? {})) {
                if (!data) continue;
                this.addEntry(index, name, data.version, data.resolved ?? '');
                if (data.dependencies) scan(data.dependencies);
            }
        };

        scan(lock.dependencies);
        return index;
    }

    /**
     * Extract a name and a version from a pnpm `packages` key.
     * Supports `name@version(peers)` (pnpm >= 6.1) and `/name/version_peers`
     * (pnpm <= 6.0).
     * @param {string} key Raw key, quotes already stripped
     * @returns {{name: string, version: string} | null}
     */
    static parsePnpmKey(key) {
        // Tested first: a legacy key also holds an `@`, so the modern pattern would match it wrong
        if (key.startsWith('/')) {
            const legacy = key.match(/^\/((?:@[^/]+\/)?[^/]+)\/([^_\s]+)(?:_.*)?$/);
            return legacy ? { name: legacy[1], version: legacy[2] } : null;
        }

        const modern = key.match(/^((?:@[^/]+\/)?[^@\s]+)@([^(\s]+)(?:\(.*\))?$/);
        return modern ? { name: modern[1], version: modern[2] } : null;
    }

    /**
     * Create an index of all packages from a pnpm-lock.yaml.
     * Minimal YAML reader tailored to the pnpm lockfile format — extracts package
     * names, versions and tarball URLs from the top-level `packages:` section.
     * @param {string} filePath Path to the pnpm-lock.yaml
     * @returns {Object}
     */
    static indexPnpmPackages(filePath = PNPM_LOCK_FILE) {
        const content = fs.readFileSync(filePath, 'utf8');
        const index = {};

        let inPackages = false;
        let current = null;

        for (const line of content.split('\n')) {
            const topLevel = line.match(/^([a-zA-Z][\w-]*):/);
            if (topLevel) {
                inPackages = topLevel[1] === 'packages';
                current = null;
                continue;
            }

            if (!inPackages) continue;

            const entry = line.match(/^ {2}'?(.+?)'?:\s*$/);
            if (entry) {
                const parsed = this.parsePnpmKey(entry[1]);
                current = parsed ? this.addEntry(index, parsed.name, parsed.version) : null;
                continue;
            }

            if (current && /^ {4}resolution:/.test(line)) {
                const tarball = line.match(/tarball:\s*([^\s,}]+)/);
                if (tarball) current.resolved = tarball[1];
            }
        }

        return index;
    }

    /**
     * Create an index of all dependencies declared in a package.json.
     * Versions are declared as ranges, so the leading range operators are
     * stripped to keep the exact-version comparison meaningful.
     * @param {string} filePath Path to the package.json
     * @returns {Object}
     */
    static indexPackageJson(filePath = PACKAGE_FILE) {
        const pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const index = {};

        const groups = [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies, pkg.peerDependencies];

        for (const group of groups) {
            if (!group) continue;
            for (const [name, range] of Object.entries(group)) {
                this.addEntry(
                    index,
                    name,
                    String(range)
                        .replace(/^[\s^~>=<]+/, '')
                        .trim()
                );
            }
        }

        return index;
    }

    /**
     * Create an index of all packages from a file, picking the right parser
     * based on the file name.
     * @param {string} filePath Path to the file to index
     * @returns {Object}
     */
    static indexFile(filePath) {
        switch (path.basename(filePath)) {
            case NPM_LOCK_FILE:
                return this.indexNpmPackages(filePath);
            case PNPM_LOCK_FILE:
                return this.indexPnpmPackages(filePath);
            case PACKAGE_FILE:
                return this.indexPackageJson(filePath);
            default:
                return {};
        }
    }

    /**
     * Check a package index against the compromised list, logging every match.
     * @param {string} processId Unique identifier for the trace process
     * @param {Object} packageIndex Index of installed/declared packages
     * @param {Object} compromisedList List of compromised packages
     * @param {string} label Prefix prepended to every log line (optional)
     * @returns {number} Number of vulnerabilities found
     */
    static checkIndex(processId, packageIndex, compromisedList, label = '') {
        let errorCount = 0;

        for (const [name, entries] of Object.entries(packageIndex)) {
            // hasOwn, so that packages named `constructor` or `toString` do not match
            if (!Object.hasOwn(compromisedList, name)) continue;
            const versions = compromisedList[name];

            for (const { version, resolved } of entries) {
                const origin = resolved ? ` (${resolved})` : '';

                if (!versions) {
                    Logger.traceWarning(
                        processId,
                        `${label}${name}@${version} => compromised package found!!!${origin}`
                    );
                    errorCount++;
                    continue;
                }

                if (versions.includes(version) || versions.some(v => resolved.includes(`-${v}.tgz`))) {
                    Logger.traceWarning(
                        processId,
                        `${label}${name}@${version} => compromised version found!!!${origin}`
                    );
                    errorCount++;
                }
            }
        }

        return errorCount;
    }

    /**
     * List every file to validate for the current run.
     * @param {{pnpm: boolean, monorepo: boolean, cwd: string}} options Run options
     * @returns {Array<string>} List of file paths
     */
    static getValidatedFiles({ pnpm, monorepo, cwd }) {
        return monorepo
            ? this.findValidatedFiles(this.findRepositoryRoot(cwd))
            : [path.join(cwd, this.getLockFileName(pnpm))];
    }

    /**
     * Validate packages based on the compromisedPackages list.
     * Fails closed: an unreachable list or an unreadable file counts as an error.
     * @param {{pnpm?: boolean, monorepo?: boolean, cwd?: string}} options Run options
     * @returns {Promise<number>} Number of vulnerabilities found
     */
    static async validateAsync(options = {}) {
        const { pnpm = this.usePnpm, monorepo = this.monorepo, cwd = process.cwd() } = options;
        const processId = PROCESS_ID;

        let compromisedList;
        try {
            compromisedList = await this.getCompromisedPackagesAsync();
        } catch (error) {
            Logger.startTrace(processId, 'validation result:');
            Logger.traceCritical(processId, `Could not fetch the compromised packages list (${error.message})`);
            Logger.endTrace(processId);
            return 1;
        }

        const files = this.getValidatedFiles({ pnpm, monorepo, cwd });
        const scope = monorepo ? `monorepo (${files.length} file(s))` : this.getLockFileName(pnpm);

        console.log(`[${processId}]`, `Starting ${scope} validation...`);
        Logger.startTrace(processId, `${scope} validation result:`);

        let errorCount = 0;

        for (const file of files) {
            const label = monorepo ? `${path.relative(cwd, file) || file}: ` : '';

            try {
                errorCount += this.checkIndex(processId, this.indexFile(file), compromisedList, label);
            } catch (error) {
                Logger.traceCritical(processId, `${file} => could not be read (${error.message})`);
                errorCount++;
            }
        }

        if (errorCount === 0) {
            Logger.traceSuccess(processId, `No vulnerability found in ${scope}`);
        } else {
            Logger.traceCritical(processId, `${errorCount} vulnerability(ies) found`);
            Logger.traceCritical(
                processId,
                pnpm
                    ? `Please remove your pnpm-lock.yaml file and node_modules folder, clean your pnpm store using 'pnpm store prune' and fix your package.json dependencies before reinstalling everything using 'pnpm install'`
                    : `Please remove your package-lock.json file and node_modules folder, clean your npm cache using 'npm cache clean --force' and fix your package.json dependencies before reinstalling everything using 'npm install'`
            );
        }
        Logger.endTrace(processId);

        return errorCount;
    }
}
