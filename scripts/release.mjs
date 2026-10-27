import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractPackage, modulePackage, versionParts } from '../update.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
if (pkg.name !== modulePackage || versionParts(pkg.version)?.value !== pkg.version) throw new Error('Invalid release identity');
const destination = resolve(process.argv[2] || join(root, 'dist'));
const temporary = mkdtempSync(join(tmpdir(), 'web-login-release-'));
try {
  const packed = JSON.parse(execFileSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', temporary], { cwd: root, encoding: 'utf8' }));
  const filename = `${modulePackage}-${pkg.version}.tgz`;
  if (packed.length !== 1 || packed[0].filename !== filename) throw new Error('Unexpected release filename');
  const archive = readFileSync(join(temporary, filename));
  const digest = createHash('sha256').update(archive).digest('hex');
  extractPackage(archive, join(temporary, 'validated'), { version: pkg.version, size: archive.length, digest });
  mkdirSync(destination, { recursive: true });
  copyFileSync(join(temporary, filename), join(destination, filename));
  writeFileSync(join(destination, `${filename}.sha256`), `${digest}  ${filename}\n`);
  console.log(`${filename}\nsha256:${digest}`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
