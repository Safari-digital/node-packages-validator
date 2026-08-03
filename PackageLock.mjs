import fs from 'fs';
import path from 'path';
import Logger from './Logger.mjs';

const NPM_LOCK_FILE = 'package-lock.json';
const PNPM_LOCK_FILE = 'pnpm-lock.yaml';
const PACKAGE_FILE = 'package.json';

const VALIDATED_FILES = [NPM_LOCK_FILE, PNPM_LOCK_FILE, PACKAGE_FILE];
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git']);

export default class PackageLock {
    static usePnpm = process.argv.includes('--pnpm');
    static monorepo = process.argv.includes('--monorepo');

    /**
     * Get the lockfile name based on the active package manager
     * @returns {string}
     */
    static getLockFileName = () => (this.usePnpm ? PNPM_LOCK_FILE : NPM_LOCK_FILE);

    /**
     * Get the content of a package-lock.json
     * @param {string} filePath Path to the package-lock.json
     * @returns {Object}
     */
    static getPackageLock = (filePath = NPM_LOCK_FILE) => JSON.parse(fs.readFileSync(filePath, 'utf8'));

    /**
     * Get the list of infected packages
     * See https://github.com/DataDog/malicious-software-packages-dataset for further information
     * @returns {Promise<{[string]: null | Array<string> }>}
     */
    static async getCompromisedPackagesAsync() {
        const source =
            'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/refs/heads/main/samples/npm/manifest.json';
        const response = await fetch(source);
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
     * Create an index of all packages in a npm package-lock.json
     * @param {string} filePath Path to the package-lock.json
     * @returns {Object}
     */
    static indexNpmPackages(filePath = NPM_LOCK_FILE) {
        const lock = this.getPackageLock(filePath);
        const deps = lock.packages ?? lock.dependencies ?? {};
        const index = {};

        function scan(obj) {
            for (const [name, data] of Object.entries(obj)) {
                if (data) {
                    index[name] = data;
                    if (data.dependencies) scan(data.dependencies);
                }
            }
        }

        scan(deps);
        return index;
    }

    /**
     * Create an index of all packages from a pnpm-lock.yaml.
     * Minimal YAML parser tailored to pnpm-lock format v6+ — extracts package
     * names, versions and tarball URLs from the top-level `packages:` section.
     * @param {string} filePath Path to the pnpm-lock.yaml
     * @returns {Object}
     */
    static indexPnpmPackages(filePath = PNPM_LOCK_FILE) {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        const index = {};

        let inPackages = false;
        let currentName = null;

        for (const line of lines) {
            const topLevel = line.match(/^([a-zA-Z][\w-]*):\s*$/);
            if (topLevel) {
                inPackages = topLevel[1] === 'packages';
                currentName = null;
                continue;
            }

            if (!inPackages) continue;

            const entry = line.match(/^ {2}'?([^':]+(?:@[^':]+)?)'?:\s*$/);
            if (entry) {
                const key = entry[1];
                const parsed = key.match(/^((?:@[^/]+\/)?[^@]+)@([^(]+?)(?:\([^)]*\))?$/);
                if (parsed) {
                    const name = parsed[1];
                    const version = parsed[2].trim();
                    currentName = name;
                    if (!index[name]) index[name] = { version, resolved: '' };
                } else {
                    currentName = null;
                }
                continue;
            }

            if (currentName && /^ {4}resolution:/.test(line)) {
                const tarball = line.match(/tarball:\s*([^\s,}]+)/);
                if (tarball) index[currentName].resolved = tarball[1];
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
                index[name] = {
                    version: String(range)
                        .replace(/^[\s^~>=<]+/, '')
                        .trim(),
                    resolved: '',
                };
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
     * Create an index of all packages from the active lockfile
     * @returns {Object}
     */
    static indexPackages() {
        return this.usePnpm ? this.indexPnpmPackages() : this.indexNpmPackages();
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

        const compromisedSet = new Set(Object.keys(compromisedList));
        const installedSet = new Set(Object.keys(packageIndex));
        const intersection = [...installedSet].filter(pkg => compromisedSet.has(pkg));

        for (const pkg of intersection) {
            const data = packageIndex[pkg];
            const versions = compromisedList[pkg];
            if (!data || !data.version) continue;

            const resolved = data.resolved ?? '';

            if (!versions) {
                Logger.traceWarning(
                    processId,
                    `${label}${pkg} => compromised package found!!! (${data.version} - ${resolved})`
                );
                errorCount++;
                continue;
            }

            const versionSet = new Set(versions);
            if (versionSet.has(data.version) || versions.some(v => resolved.includes(`-${v}.tgz`))) {
                Logger.traceWarning(
                    processId,
                    `${label}${pkg} => ${data.version} compromised version found!!! (${resolved})`
                );
                errorCount++;
            }
        }

        return errorCount;
    }

    /**
     * Validate packages based on the compromisedPackages list
     * @returns {Promise<void>}
     */
    static async validateAsync() {
        const processId = 'PACKAGE-LOCK-VALIDATION';
        const compromisedList = await this.getCompromisedPackagesAsync();

        const files = this.monorepo ? this.findValidatedFiles(this.findRepositoryRoot()) : [this.getLockFileName()];
        const scope = this.monorepo ? `monorepo (${files.length} file(s))` : this.getLockFileName();

        console.log(`[${processId}]`, `Starting ${scope} validation...`);
        Logger.startTrace(processId, `${scope} validation result:`);

        let errorCount = 0;

        for (const file of files) {
            try {
                const index = this.indexFile(file);
                errorCount += this.checkIndex(processId, index, compromisedList, this.monorepo ? `${file}: ` : '');
            } catch (error) {
                Logger.traceWarning(processId, `${file} => could not be read (${error.message})`);
            }
        }

        if (errorCount === 0) {
            Logger.traceSuccess(processId, `No vulnerability found in ${scope}`);
        } else {
            Logger.traceCritical(processId, `${errorCount} vulnerability(ies) found`);
            Logger.traceCritical(
                processId,
                this.usePnpm
                    ? `Please remove your pnpm-lock.yaml file and node_modules folder, clean your pnpm store using 'pnpm store prune' and fix your package.json dependencies before reinstalling everything using 'pnpm install'`
                    : `Please remove your package-lock.json file and node_modules folder, clean your npm cache using 'npm cache clean --force' and fix your package.json dependencies before reinstalling everything using 'npm install'`
            );
        }
        Logger.endTrace(processId);
    }
}
