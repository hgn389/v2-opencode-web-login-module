import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareVersions, extractPackage, latestRelease, moduleFiles, modulePackage, repository } from '../update.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

test('module updates use only the new repository, exact asset path and GitHub SHA-256 digest', async () => {
  assert.equal(repository, 'hgn389/v2-opencode-web-login-module');
  assert.equal(modulePackage, 'v2-opencode-web-login-module');
  assert.equal(pkg.name, modulePackage);
  assert.match(pkg.version, /^\d+\.\d+\.\d+-beta\.\d+$/);
  const lock = JSON.parse(readFileSync(join(root, 'npm-shrinkwrap.json'), 'utf8'));
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  assert(compareVersions(pkg.version, '1.2.2-beta') > 0);
  const filename = `${modulePackage}-${pkg.version}.tgz`;
  const url = `https://github.com/${repository}/releases/download/v${pkg.version}/${filename}`;
  const asset = { name: filename, state: 'uploaded', size: 100, digest: `sha256:${'a'.repeat(64)}`, browser_download_url: url };
  const check = async (override = {}, releaseOverride = {}) => latestRelease('1.2.2-beta', 'beta', {
    read: async endpoint => {
      assert.equal(endpoint, `https://api.github.com/repos/${repository}/releases?per_page=100`);
      return Buffer.from(JSON.stringify([{ tag_name: `v${pkg.version}`, prerelease: true, assets: [{ ...asset, ...override }], ...releaseOverride }]));
    },
  });
  const release = await check();
  assert.equal(release.assetURL, url);
  assert.equal(release.digest, 'a'.repeat(64));
  for (const override of [
    { name: `opencode-web-login-${pkg.version}.tgz` },
    { browser_download_url: url.replace(repository, 'hgn389/opencode-web-login-module') },
    { browser_download_url: url.replace(repository, 'attacker/v2-opencode-web-login-module') },
    { browser_download_url: url.replace('/download/v', '/download/') },
    { browser_download_url: `${url}?download=1` },
    { browser_download_url: url.replace('https:', 'http:') },
    { digest: undefined }, { digest: `sha512:${'a'.repeat(64)}` },
    { digest: `sha256:${'A'.repeat(64)}` }, { digest: `sha256:${'a'.repeat(63)}` },
    { size: 0 }, { size: 8 * 1024 * 1024 + 1 }, { state: 'new' },
  ]) await assert.rejects(check(override), /Release asset or SHA-256 digest missing/);
  assert.equal(await check({}, { tag_name: `v${pkg.version}/../../evil` }), null);
  assert.equal(await check({}, { draft: true }), null);
});

test('release packaging produces an updater-compatible allowlisted archive and checksum', () => {
  const directory = mkdtempSync(join(tmpdir(), 'web-login-release-test-'));
  try {
    execFileSync(process.execPath, ['scripts/release.mjs', directory], { cwd: root, encoding: 'utf8' });
    const filename = `${modulePackage}-${pkg.version}.tgz`;
    const archive = readFileSync(join(directory, filename));
    const digest = createHash('sha256').update(archive).digest('hex');
    assert.equal(readFileSync(join(directory, `${filename}.sha256`), 'utf8'), `${digest}  ${filename}\n`);
    const expected = { version: pkg.version, size: archive.length, digest };
    extractPackage(archive, join(directory, 'extracted'), expected);
    for (const file of moduleFiles) assert(existsSync(join(directory, 'extracted', file)), file);
    for (const file of ['test/live-clean-readonly.mjs', 'HANDOFF.md', 'Readme.md', 'scripts/release.mjs', '.git/config']) {
      assert(!moduleFiles.includes(file));
      assert(!existsSync(join(directory, 'extracted', file)));
    }
    assert.throws(() => extractPackage(archive, join(directory, 'bad-digest'), { ...expected, digest: '0'.repeat(64) }), /digest mismatch/);
    assert.throws(() => extractPackage(archive, join(directory, 'bad-size'), { ...expected, size: archive.length + 1 }), /digest mismatch/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
