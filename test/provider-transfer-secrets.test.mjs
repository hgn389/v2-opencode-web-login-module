import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync, chmodSync, symlinkSync, linkSync, lstatSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { providerFileOperation } from '../admin-service.mjs';

const providerPackage = '@opencode/ai/providers/openai-compatible';
const fixture = t => {
  const root = mkdtempSync(join(tmpdir(), 'provider-secrets-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const context = { directory: join(root, 'config'), backupDirectory: join(root, 'backups') };
  mkdirSync(context.directory, { mode: 0o700 });
  const file = join(context.directory, 'opencode.json');
  writeFileSync(file, '{}\n', { mode: 0o600 });
  const call = request => providerFileOperation(context, request);
  return { root, context, file, call, import: providers => call({ action: 'import', providers, revision: call({ action: 'read' }).revision }) };
};

test('secret backups round-trip into new immutable files and restore removes every imported key', t => {
  const source = fixture(t), destination = fixture(t);
  const providers = ['alpha', 'beta'].map(id => ({ id, name: id, baseURL: 'https://api.example.com/v1', allowHttp: false, models: [{ id: 'coder', name: 'Coder' }], apiKey: 'isolated-roundtrip-' + id }));
  source.import(providers);
  const sourceBefore = readFileSync(source.file, 'utf8');
  const sourceFiles = readdirSync(source.context.backupDirectory);
  const noSecrets = source.call({ action: 'export', includeSecrets: false });
  assert.deepEqual(noSecrets.backup.providers, providers.map(({ apiKey, ...provider }) => provider));
  assert(!JSON.stringify(noSecrets).includes('.web-login-secrets'));
  const exported = source.call({ action: 'export', includeSecrets: true });
  assert.deepEqual(exported, { status: 200, backup: { format: 'opencode-web-login-providers', version: 1, providers } });
  assert.equal(readFileSync(source.file, 'utf8'), sourceBefore);
  assert.deepEqual(readdirSync(source.context.backupDirectory), sourceFiles);
  const saved = destination.import(exported.backup.providers);
  const persisted = readFileSync(destination.file, 'utf8'), data = JSON.parse(persisted);
  const keys = providers.map(provider => data.providers[provider.id].settings.apiKey.slice(6, -1));
  for (const [index, key] of keys.entries()) {
    assert.equal(dirname(key), join(destination.context.directory, '.web-login-secrets'));
    assert.equal(lstatSync(key).mode & 0o777, 0o600);
    assert.equal(readFileSync(key, 'utf8'), providers[index].apiKey);
    assert(!persisted.includes(providers[index].apiKey));
    assert(!sourceBefore.includes(key));
  }
  assert.deepEqual(destination.call({ action: 'export', includeSecrets: true }).backup, exported.backup);
  destination.call({ action: 'restore', backup: saved.backup });
  assert.equal(readFileSync(destination.file, 'utf8'), '{}\n');
  keys.forEach(key => assert(!existsSync(key)));
});

test('secret export rejects malicious references without disclosing values and false never resolves them', t => {
  const f = fixture(t), secretDirectory = join(f.context.directory, '.web-login-secrets');
  mkdirSync(secretDirectory, { mode: 0o700 });
  const secret = 'isolated-never-disclose';
  const key = join(secretDirectory, 'owned.key'), external = join(f.root, 'external.key');
  writeFileSync(key, secret, { mode: 0o600 });
  writeFileSync(external, secret, { mode: 0o600 });
  const symlink = join(secretDirectory, 'symlink.key'), hardlink = join(secretDirectory, 'hardlink.key');
  symlinkSync(external, symlink); linkSync(external, hardlink);
  const base = { name: 'API', package: providerPackage, settings: { baseURL: 'https://api.example.com/v1' }, models: { coder: { name: 'Coder' } } };
  const invalid = [
    { settings: { ...base.settings, apiKey: '{env:SECRET}' } },
    { settings: { ...base.settings, apiKey: '${SECRET}' } },
    { settings: { ...base.settings, apiKey: `{file:${external}}` } },
    { settings: { ...base.settings, apiKey: `{file:${secretDirectory}/../.web-login-secrets/owned.key}` } },
    { settings: { ...base.settings, apiKey: `{file:${symlink}}` } },
    { settings: { ...base.settings, apiKey: `{file:${hardlink}}` } },
    { settings: { ...base.settings, apiKey: `{file:${secretDirectory}/missing.key}` } },
    { settings: { ...base.settings, apiKey: { env: 'SECRET' } } },
    ...[null, false, 0].map(apiKey => ({ settings: { ...base.settings, apiKey } })),
    { env: ['SECRET'] },
    { headers: { Authorization: secret } },
    { settings: { ...base.settings, apiKey: 'invalid key' } },
  ];
  for (const fields of invalid) {
    writeFileSync(f.file, JSON.stringify({ providers: { custom: { ...base, ...fields } } }));
    assert.throws(() => f.call({ action: 'export', includeSecrets: true }), error => error.status === 422 && !error.message.includes(secret) && !error.message.includes(external));
    const result = JSON.stringify(f.call({ action: 'export', includeSecrets: false }));
    for (const forbidden of [secret, 'apiKey', '{file:', '{env:', '${', 'Authorization', external]) assert(!result.includes(forbidden));
    assert(!existsSync(f.context.backupDirectory));
  }
  writeFileSync(f.file, JSON.stringify({ providers: { custom: { ...base, settings: { ...base.settings, apiKey: `{file:${key}}` } } } }));
  chmodSync(key, 0o644);
  assert.throws(() => f.call({ action: 'export', includeSecrets: true }), /Cannot safely/);
  chmodSync(key, 0o600); chmodSync(secretDirectory, 0o755);
  assert.throws(() => f.call({ action: 'export', includeSecrets: true }), /Cannot safely/);
});

test('export is read-only, requires boolean consent and rejects whole unsupported or oversized sets', t => {
  const f = fixture(t);
  for (const includeSecrets of [undefined, null, 0, 'false']) assert.throws(() => f.call({ action: 'export', includeSecrets }), /boolean/);
  assert.deepEqual(f.call({ action: 'export', includeSecrets: false }).backup.providers, []);
  const base = { package: providerPackage, settings: { baseURL: 'https://api.example.com/v1' }, models: { coder: {} } };
  const cases = [
    [{ custom: { ...base, package: 'unsupported' } }, /OpenAI-compatible/],
    [Object.fromEntries(Array.from({ length: 101 }, (_, i) => ['p' + i, base])), /100/],
    [{ first: { ...base, models: Object.fromEntries(Array.from({ length: 2000 }, (_, i) => ['m' + i, {}])) }, last: base }, /2000/],
  ];
  for (const [providers, message] of cases) {
    const text = JSON.stringify({ providers }); writeFileSync(f.file, text);
    assert.throws(() => f.call({ action: 'export', includeSecrets: false }), message);
    assert.equal(readFileSync(f.file, 'utf8'), text);
    assert(!existsSync(f.context.backupDirectory));
  }
  rmSync(f.context.directory, { recursive: true });
  assert.throws(() => f.call({ action: 'export', includeSecrets: false }));
  assert(!existsSync(f.context.directory));
});

test('export bounds the entire serialized response including resolved keys and expanded model names', t => {
  const f = fixture(t), secretDirectory = join(f.context.directory, '.web-login-secrets');
  mkdirSync(secretDirectory, { mode: 0o700 });
  const models = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [('m' + i).padEnd(128, '\u4e00'), {}]));
  const providers = Object.fromEntries(Array.from({ length: 100 }, (_, i) => {
    const key = join(secretDirectory, 'p' + i + '.key');
    writeFileSync(key, 'k'.repeat(4096), { mode: 0o600 });
    return ['p' + i, { package: providerPackage, settings: { baseURL: 'https://api.example.com/' + 'a'.repeat(1970), apiKey: `{file:${key}}` }, models }];
  }));
  const text = JSON.stringify({ providers });
  assert(Buffer.byteLength(text) < 1024 * 1024);
  writeFileSync(f.file, text);
  assert.equal(f.call({ action: 'export', includeSecrets: false }).backup.providers.length, 100);
  assert.throws(() => f.call({ action: 'export', includeSecrets: true }), /2 MiB/);
  assert.equal(readFileSync(f.file, 'utf8'), text);
  assert(!existsSync(f.context.backupDirectory));
});
