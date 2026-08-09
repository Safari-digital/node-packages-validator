import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import PackageLock from '../PackageLock.mjs';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

const fixture = (...segments) => path.join(FIXTURES, ...segments);
const versions = (index, name) => (index[name] ?? []).map(entry => entry.version).sort();

/**
 * Replace the network call and silence the trace output for a single test.
 * @param {import('node:test').TestContext} t Running test context
 * @param {Object | Error} list Compromised list to serve, or the failure to raise
 */
const stub = (t, list) => {
    t.mock.method(console, 'log', () => undefined);
    t.mock.method(PackageLock, 'getCompromisedPackagesAsync', async () => {
        if (list instanceof Error) throw list;
        return list;
    });
};

test('resolves npm lockfile paths back to package names', () => {
    const index = PackageLock.indexNpmPackages(fixture('npm', 'package-lock.json'));

    assert.deepEqual(Object.keys(index).sort(), ['@scope/tool', 'debug', 'left-pad', 'real-package']);
    assert.deepEqual(versions(index, 'left-pad'), ['1.3.0']);
    assert.equal(index['@scope/tool'][0].resolved, 'https://registry.npmjs.org/@scope/tool/-/tool-2.0.0.tgz');
});

test('keeps every version of a package installed more than once', () => {
    const index = PackageLock.indexNpmPackages(fixture('npm', 'package-lock.json'));
    assert.deepEqual(versions(index, 'debug'), ['4.3.4', '4.4.1']);
});

test('follows npm aliases to the real package name', () => {
    const index = PackageLock.indexNpmPackages(fixture('npm', 'package-lock.json'));

    assert.deepEqual(versions(index, 'real-package'), ['9.9.9']);
    assert.equal(index.aliased, undefined);
});

test('ignores the root project and workspace links', () => {
    const index = PackageLock.indexNpmPackages(fixture('npm', 'package-lock.json'));

    assert.equal(index['npm-fixture'], undefined);
    assert.equal(index['workspace-pkg'], undefined);
});

test('reads the legacy npm dependencies tree', () => {
    const index = PackageLock.indexNpmPackages(fixture('npm-legacy', 'package-lock.json'));

    assert.deepEqual(Object.keys(index).sort(), ['debug', 'left-pad']);
    assert.deepEqual(versions(index, 'debug'), ['4.3.4', '4.4.1']);
});

test('indexes scoped, plain and peer-suffixed pnpm keys', () => {
    const index = PackageLock.indexPnpmPackages(fixture('pnpm', 'pnpm-lock.yaml'));

    assert.deepEqual(versions(index, '@scope/tool'), ['2.0.0']);
    assert.deepEqual(versions(index, 'left-pad'), ['1.3.0']);
    assert.deepEqual(versions(index, 'vue-eslint-parser'), ['10.4.0']);
});

test('keeps every version of a pnpm lockfile', () => {
    const index = PackageLock.indexPnpmPackages(fixture('pnpm', 'pnpm-lock.yaml'));
    assert.deepEqual(versions(index, 'debug'), ['4.3.4', '4.4.1']);
});

test('captures pnpm tarball resolutions', () => {
    const index = PackageLock.indexPnpmPackages(fixture('pnpm', 'pnpm-lock.yaml'));
    assert.equal(index.tarballed[0].resolved, 'https://example.com/tarballed-1.0.0.tgz');
});

test('stops indexing at the end of the packages section', () => {
    const index = PackageLock.indexPnpmPackages(fixture('pnpm', 'pnpm-lock.yaml'));
    assert.equal(index['only-in-snapshots'], undefined);
});

test('reads legacy pnpm keys', () => {
    const index = PackageLock.indexPnpmPackages(fixture('pnpm-legacy', 'pnpm-lock.yaml'));

    assert.deepEqual(Object.keys(index).sort(), ['@scope/tool', 'debug', 'vue-eslint-parser']);
    assert.deepEqual(versions(index, 'vue-eslint-parser'), ['9.0.0']);
});

test('strips range operators declared in a package.json', () => {
    const index = PackageLock.indexPackageJson(fixture('manifest', 'package.json'));

    assert.deepEqual(versions(index, 'left-pad'), ['1.3.0']);
    assert.deepEqual(versions(index, 'debug'), ['4.3.4']);
    assert.deepEqual(versions(index, '@scope/tool'), ['2.0.0']);
    assert.deepEqual(versions(index, 'eslint'), ['9.39.4']);
});

test('picks the parser from the file name', () => {
    assert.ok(PackageLock.indexFile(fixture('pnpm', 'pnpm-lock.yaml')).debug);
    assert.ok(PackageLock.indexFile(fixture('npm', 'package-lock.json')).debug);
    assert.ok(PackageLock.indexFile(fixture('manifest', 'package.json')).debug);
    assert.deepEqual(PackageLock.indexFile(fixture('manifest', 'unknown.txt')), {});
});

test('flags every version when the dataset lists none', () => {
    const index = PackageLock.indexNpmPackages(fixture('npm', 'package-lock.json'));
    assert.equal(PackageLock.checkIndex('TEST', index, { debug: null }), 2);
});

test('flags only the versions listed by the dataset', () => {
    const index = PackageLock.indexNpmPackages(fixture('npm', 'package-lock.json'));

    assert.equal(PackageLock.checkIndex('TEST', index, { debug: ['4.4.1'] }), 1);
    assert.equal(PackageLock.checkIndex('TEST', index, { debug: ['1.0.0'] }), 0);
    assert.equal(PackageLock.checkIndex('TEST', index, { 'not-installed': null }), 0);
});

test('matches a compromised version through its tarball url', () => {
    const index = { thing: [{ version: 'unknown', resolved: 'https://registry.npmjs.org/thing/-/thing-6.6.6.tgz' }] };
    assert.equal(PackageLock.checkIndex('TEST', index, { thing: ['6.6.6'] }), 1);
});

test('does not flag packages named after an Object prototype member', () => {
    const index = { constructor: [{ version: '1.0.0', resolved: '' }], toString: [{ version: '1.0.0', resolved: '' }] };
    assert.equal(PackageLock.checkIndex('TEST', index, {}), 0);
});

test('walks a repository for every validated file', () => {
    const found = PackageLock.findValidatedFiles(FIXTURES).map(file => path.basename(file));

    assert.equal(found.length, 5);
    assert.equal(found.filter(name => name === 'package-lock.json').length, 2);
    assert.equal(found.filter(name => name === 'pnpm-lock.yaml').length, 2);
    assert.equal(found.filter(name => name === 'package.json').length, 1);
});

test('returns the number of vulnerabilities found', async t => {
    stub(t, { debug: null });
    assert.equal(await PackageLock.validateAsync({ pnpm: true, cwd: fixture('pnpm') }), 2);
});

test('returns zero when nothing matches', async t => {
    stub(t, { 'not-installed': null });
    assert.equal(await PackageLock.validateAsync({ pnpm: true, cwd: fixture('pnpm') }), 0);
});

test('validates every file of a monorepo in a single pass', async t => {
    stub(t, { debug: ['4.4.1'] });
    t.mock.method(PackageLock, 'findRepositoryRoot', () => FIXTURES);

    assert.equal(await PackageLock.validateAsync({ monorepo: true, cwd: FIXTURES }), 3);
});

test('fails closed when the dataset cannot be fetched', async t => {
    stub(t, new Error('network is unreachable'));
    assert.equal(await PackageLock.validateAsync({ pnpm: true, cwd: fixture('pnpm') }), 1);
});

test('fails closed when the lockfile cannot be read', async t => {
    stub(t, {});
    assert.equal(await PackageLock.validateAsync({ cwd: fixture('pnpm') }), 1);
});
