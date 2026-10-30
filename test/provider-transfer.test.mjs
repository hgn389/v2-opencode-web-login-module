import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, readdirSync, existsSync, lstatSync, symlinkSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { parse } from 'jsonc-parser';
import { createAdminController, providerFileOperation } from '../admin-service.mjs';
import { createLoginServer } from '../index.mjs';
import { SecurityStore } from '../security.mjs';

const provider = (id = 'imported') => ({ id, name: 'Imported API', baseURL: 'https://api.example.com/v1', models: [{ id: 'coder', name: 'Coder' }], allowHttp: false });
const fixture = () => {
  const directory = mkdtempSync(join(tmpdir(), 'provider-transfer-'));
  const context = { directory: join(directory, 'config'), backupDirectory: join(directory, 'backups') };
  mkdirSync(context.directory, { mode: 0o700 });
  const file = join(context.directory, 'opencode.jsonc');
  const original = '{\n // retained comment\n "model":"existing/coder",\n "providers":{"existing":{"package":"other-package","settings":{"apiKey":"retained-secret"},"models":{"coder":{}}}},\n "shell":"/bin/bash",\n}\n';
  writeFileSync(file, original, { mode: 0o600 });
  const read = () => providerFileOperation(context, { action: 'read' });
  const importProviders = providers => providerFileOperation(context, { action: 'import', revision: read().revision, providers });
  return { directory, context, file, original, read, importProviders, close: () => rmSync(directory, { recursive: true, force: true }) };
};

test('provider import is one private snapshot with atomic JSONC preservation and exact rollback', () => {
  const f = fixture();
  try {
    const saved = f.importProviders([provider('first'), provider('second')]);
    assert.equal(saved.status, 200);
    assert.equal(readdirSync(f.context.backupDirectory).filter(name => name.startsWith('snapshot-')).length, 1);
    const text = readFileSync(f.file, 'utf8'), data = parse(text, [], { allowTrailingComma: true });
    assert(text.includes('// retained comment'));
    assert.equal(data.model, 'existing/coder');
    assert.equal(data.providers.existing.settings.apiKey, 'retained-secret');
    for (const id of ['first', 'second']) {
      assert.deepEqual(data.providers[id], { name: 'Imported API', package: '@opencode/ai/providers/openai-compatible', settings: { baseURL: provider().baseURL }, models: { coder: { name: 'Coder' } } });
      assert.equal(f.read().providers.find(item => item.id === id).hasKey, false);
    }
    assert(!JSON.stringify(f.read()).includes('retained-secret'));
    providerFileOperation(f.context, { action: 'restore', backup: saved.backup });
    assert.equal(readFileSync(f.file, 'utf8'), f.original);
  } finally { f.close(); }
});

test('provider import rejects credentials, arbitrary fields and malformed batches without partial changes', () => {
  const f = fixture();
  try {
    const invalid = [[], null, [provider(), provider()], [provider(), provider('existing')],
      ...['env', 'headers', 'package', 'clearKey', 'allowPrivate', '__proto__'].map(key => [JSON.parse(JSON.stringify(provider()).replace('"id":', `"${key}":"forbidden-secret","id":`))]),
      [{ ...provider(), apiKey: '{env:SECRET}' }], [{ ...provider(), apiKey: 'bad key' }], [{ ...provider(), apiKey: {} }],
      [{ ...provider(), allowHttp: 'true' }], [{ ...provider(), allowHttp: undefined }], [{ ...provider(), baseURL: 'http://localhost:8000/v1' }],
      [{ ...provider(), models: [{ id: 'coder', apiKey: 'forbidden-secret' }] }], [{ ...provider(), models: [{ id: 'x' }, { id: 'x' }] }],
      [{ ...provider(), baseURL: 'https://user:secret@example.com/v1' }], [{ ...provider(), name: '{env:SECRET}' }],
      Array.from({ length: 101 }, (_, i) => provider('p' + i)),
      [provider('first'), { ...provider('last'), models: Array.from({ length: 2000 }, (_, i) => ({ id: 'm' + i })) }],
    ];
    for (const providers of invalid) {
      assert.throws(() => f.importProviders(providers));
      assert.equal(readFileSync(f.file, 'utf8'), f.original);
      assert.equal(readdirSync(f.context.backupDirectory).filter(name => name.startsWith('snapshot-')).length, 0);
    }
    assert.throws(() => f.importProviders([{ ...provider(), models: Array.from({ length: 2000 }, (_, i) => ({ id: 'm' + i })) }]), /2000/);
    assert.throws(() => f.importProviders(Array.from({ length: 100 }, (_, i) => provider('p' + i))), /100/);
    f.importProviders([{ ...provider(), baseURL: 'http://localhost:8000/v1', allowHttp: true }]);
  } finally { f.close(); }
});

test('provider import refuses malformed source, stale revisions and rollback over external edits', () => {
  const f = fixture();
  try {
    assert.throws(() => providerFileOperation(f.context, { action: 'import', revision: '0'.repeat(64), providers: [provider()] }), /thay đổi/);
    for (const text of ['{"providers":{},"providers":{}}', '{invalid', '{"providers":[]}']) {
      writeFileSync(f.file, text);
      assert.throws(() => f.importProviders([provider()]));
      assert.equal(readFileSync(f.file, 'utf8'), text);
    }
    writeFileSync(f.file, f.original);
    const saved = f.importProviders([provider()]);
    const edited = readFileSync(f.file, 'utf8') + '\n// external edit\n';
    writeFileSync(f.file, edited);
    assert.throws(() => providerFileOperation(f.context, { action: 'restore', backup: saved.backup }), /không ghi đè/);
    assert.equal(readFileSync(f.file, 'utf8'), edited);
  } finally { f.close(); }
});

const waitJob = async controller => {
  for (let i = 0; i < 100; i++) {
    const result = await controller.call({ operation: 'providers-status' });
    if (result.job.phase !== 'running') return result;
    await new Promise(done => setTimeout(done, 20));
  }
  assert.fail('Import job did not finish');
};

test('import jobs preflight every ID, verify every provider, preserve secrets on rollback and persist no input', async () => {
  for (const scenario of ['success', 'collision', 'reload-failure', 'rollback-conflict', 'credential-change', 'worker-response-lost']) {
    const f = fixture(), lookups = [], reloads = [], operations = [];
    writeFileSync(join(f.directory, 'package.json'), '{"version":"1.1.2-beta"}');
    const stateDir = join(f.directory, 'state'); let password = 'isolated-admin-password';
    const controller = createAdminController({ installDirectory: f.directory }, { stateDir, password: () => password,
      providerContext: async () => f.context,
      providerWorker: async (context, request) => {
        operations.push(request.action);
        const result = providerFileOperation(context, request);
        if (scenario === 'worker-response-lost' && request.action === 'import') throw new Error('Worker response lost after commit');
        return result;
      },
      providerExists: async id => { lookups.push(id); if (scenario === 'credential-change') password = 'rotated-password'; return scenario === 'collision' && id === 'second'; },
      providerReload: async (id, models, remove, baseURL) => {
        reloads.push(id);
         if (id && !remove) { assert.equal(models[0].id, 'coder'); assert.equal(baseURL, provider().baseURL); }
         if (remove) { assert.deepEqual(models, []); assert(!f.read().providers.some(provider => provider.id === id)); }
         if (id === 'second' && !remove && ['reload-failure', 'rollback-conflict'].includes(scenario)) {
          if (scenario === 'rollback-conflict') writeFileSync(f.file, readFileSync(f.file, 'utf8') + '\n// concurrent change\n');
          throw new Error('Injected reload failure');
        }
      },
    });
    try {
      const fields = { operation: 'provider-import', revision: f.read().revision, acknowledge: true, providers: [{ ...provider('first'), apiKey: 'private-first' }, { ...provider('second'), apiKey: 'private-second' }] };
      assert.equal((await controller.call({ ...fields, acknowledge: false })).status, 422);
      assert.equal((await controller.call({ ...fields, apiKey: 'must-not-persist' })).status, 422);
      assert.equal((await controller.call({ ...fields, providers: [{ ...provider(), apiKey: '{env:must-not-persist}' }] })).status, 422);
      assert.equal((await controller.call(fields)).status, 202);
      assert.equal((await controller.call(fields)).status, 409);
      const result = await waitJob(controller);
      assert.equal(result.job.type, 'providers');
      assert.equal(result.job.phase, scenario === 'success' ? 'succeeded' : 'failed');
      assert.deepEqual(lookups, ['first', 'second']);
      assert.equal(operations.filter(action => action === 'import').length, ['collision', 'credential-change'].includes(scenario) ? 0 : 1);
      if (scenario === 'success') assert.deepEqual(reloads, ['first', 'second']);
       if (scenario === 'reload-failure') { assert.deepEqual(reloads, ['first', 'second', 'first', 'second']); assert.equal(result.job.recoveryRequired, false); }
      if (!['success', 'rollback-conflict', 'worker-response-lost'].includes(scenario)) assert.equal(readFileSync(f.file, 'utf8'), f.original);
      if (scenario === 'reload-failure') assert.deepEqual(readdirSync(join(f.context.directory, '.web-login-secrets')), []);
      if (['rollback-conflict', 'worker-response-lost'].includes(scenario)) {
        assert.equal(result.job.recoveryRequired, true);
        assert.equal((await controller.call(fields)).status, 409);
      }
      const persisted = readFileSync(join(stateDir, 'job.json'), 'utf8');
      for (const text of ['private-first', 'private-second', 'must-not-persist', 'retained-secret', 'Imported API', 'api.example.com', '"models"', '"providers"' + ':[' ]) assert(!persisted.includes(text));
      assert(!JSON.stringify(result).includes('retained-secret'));
      assert(existsSync(f.file));
    } finally { f.close(); }
  }
});

test('multi-provider key import uses private immutable files and removes every new file on rollback', () => {
  const f = fixture();
  try {
    const providers = ['first', 'second'].map(id => ({ ...provider(id), apiKey: 'private-' + id }));
    const saved = f.importProviders(providers), text = readFileSync(f.file, 'utf8');
    const data = parse(text, [], { allowTrailingComma: true });
    const keys = providers.map(provider => data.providers[provider.id].settings.apiKey.slice(6, -1));
    assert.notEqual(keys[0], keys[1]);
    keys.forEach((key, i) => {
      assert.equal(readFileSync(key, 'utf8'), providers[i].apiKey);
      assert.equal(lstatSync(key).mode & 0o777, 0o600);
      assert(!text.includes(providers[i].apiKey));
    });
    const manifest = JSON.parse(readFileSync(join(f.context.backupDirectory, saved.backup, 'manifest.json')));
    assert.equal(manifest.entries.length, 3);
    assert(!JSON.stringify(manifest).includes('private-first'));
    providerFileOperation(f.context, { action: 'restore', backup: saved.backup });
    assert.equal(readFileSync(f.file, 'utf8'), f.original);
    keys.forEach(key => assert(!existsSync(key)));
  } finally { f.close(); }
});

test('export omits keys by default, reads only safe managed refs or literals and never persists', () => {
  const f = fixture();
  try {
    writeFileSync(f.file, '{}');
    f.importProviders([{ ...provider('managed'), apiKey: 'isolated-managed-secret' }, provider('literal')]);
    let data = parse(readFileSync(f.file, 'utf8'));
    data.providers.literal.settings.apiKey = 'isolated-literal-secret';
    writeFileSync(f.file, JSON.stringify(data));
    const before = readFileSync(f.file, 'utf8'), backups = readdirSync(f.context.backupDirectory);
    const exported = includeSecrets => providerFileOperation(f.context, { action: 'export', includeSecrets });
    assert.throws(() => exported(), /boolean/);
    assert(!JSON.stringify(exported(false)).includes('isolated-'));
    const result = exported(true);
    assert.equal(result.backup.format, 'opencode-web-login-providers'); assert.equal(result.backup.version, 1);
    assert.deepEqual(result.backup.providers.map(item => item.apiKey), ['isolated-managed-secret', 'isolated-literal-secret']);
    assert.equal(readFileSync(f.file, 'utf8'), before);
    assert.deepEqual(readdirSync(f.context.backupDirectory), backups);
    const key = data.providers.managed.settings.apiKey.slice(6, -1);
    for (const fields of [ { env: ['SECRET'] }, { headers: { Authorization: 'isolated-header' } }, { settings: { baseURL: provider().baseURL, apiKey: '{file:/etc/passwd}' } }, { settings: { baseURL: provider().baseURL, apiKey: '{env:SECRET}' } } ]) {
      writeFileSync(f.file, JSON.stringify({ providers: { managed: { ...data.providers.managed, ...fields } } }));
      assert.throws(() => exported(true), /Cannot export/);
      assert(!JSON.stringify(exported(false)).includes('isolated-'));
    }
    writeFileSync(f.file, before);
    chmodSync(key, 0o644); assert.throws(() => exported(true), /Cannot safely/); chmodSync(key, 0o600);
    rmSync(key); symlinkSync(f.file, key); assert.throws(() => exported(true), /Cannot safely/);
  } finally { f.close(); }
});

test('export controller is read-only, opt-in, busy guarded and discards secrets after credential rotation', async () => {
  const f = fixture(), stateDir = join(f.directory, 'state'); let password = 'isolated-password', rotate = false;
  writeFileSync(join(f.directory, 'package.json'), '{"version":"1.1.2-beta"}');
  writeFileSync(f.file, '{}');
  f.importProviders([{ ...provider(), apiKey: 'isolated-export-secret' }]);
  const controller = createAdminController({ installDirectory: f.directory }, { stateDir, password: () => password, providerContext: async () => f.context,
    providerWorker: async (context, request) => { const result = providerFileOperation(context, request); if (rotate) password = 'rotated'; return result; },
    providerExists: async () => false, providerReload: async () => {},
  });
  try {
    assert.equal((await controller.call({ operation: 'provider-export', includeSecrets: 'true' })).status, 422);
    assert.equal((await controller.call({ operation: 'provider-export', arbitrary: true })).status, 422);
    assert.equal((await controller.call({ operation: 'provider-export' })).status, 422);
    assert(!JSON.stringify(await controller.call({ operation: 'provider-export', includeSecrets: false })).includes('isolated-export-secret'));
    assert.equal((await controller.call({ operation: 'provider-export', includeSecrets: true })).backup.providers[0].apiKey, 'isolated-export-secret');
    assert(!existsSync(join(stateDir, 'job.json')));
    rotate = true;
    const rejected = await controller.call({ operation: 'provider-export', includeSecrets: true });
    assert.equal(rejected.status, 401); assert(!JSON.stringify(rejected).includes('isolated-export-secret'));
    rotate = false;
    assert.equal((await controller.call({ operation: 'provider-import', revision: f.read().revision, acknowledge: true, providers: [provider('next')] })).status, 202);
    assert.equal((await controller.call({ operation: 'provider-export', includeSecrets: true })).status, 409);
    await waitJob(controller);
    assert(!readFileSync(join(stateDir, 'job.json'), 'utf8').includes('isolated-export-secret'));
  } finally { f.close(); }
});

test('import API enforces auth, CSRF, origin, POST, strict fields and 2MiB body limit', async () => {
  const f = fixture(), socket = join(f.directory, 'admin.sock'); let forwarded;
  const helper = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    forwarded = JSON.parse(Buffer.concat(chunks));
    const result = forwarded.operation === 'providers-status' ? { status: 200, providers: { revision: 'a'.repeat(64), providers: [] } } : { status: 202, message: 'Accepted' };
    res.writeHead(result.status, { 'content-type': 'application/json' }); res.end(JSON.stringify(result));
  });
  const backend = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}'); });
  helper.listen(socket); backend.listen(0, '127.0.0.1');
  await Promise.all([once(helper, 'listening'), once(backend, 'listening')]);
  const reserve = http.createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  const port = reserve.address().port; await new Promise(done => reserve.close(done));
  const origin = `http://127.0.0.1:${port}`, database = join(f.directory, 'gateway.sqlite');
  const gateway = createLoginServer({ port, backendPort: backend.address().port, statePath: database, adminSocket: socket });
  const store = new SecurityStore(database), cookie = `opencode_login_${port}=${store.createSession('isolated-token', origin)}`;
  await gateway.listen();
  const request = (options = {}) => fetch(origin + '/web-login/api/provider-import', { ...options, headers: { cookie, 'x-opencode-login': '1', ...options.headers } });
  try {
    const status = await (await fetch(origin + '/web-login/api/providers-status', { headers: { cookie, 'x-opencode-login': '1' } })).json();
    const options = { method: 'POST', headers: { origin, 'content-type': 'application/json', 'x-web-login-csrf': status.csrf }, body: JSON.stringify({ revision: 'a'.repeat(64), acknowledge: true, providers: [provider()] }) };
    assert.equal((await fetch(origin + '/web-login/api/provider-import', options)).status, 401);
    assert.equal((await request({ headers: options.headers })).status, 403);
    assert.equal((await request({ ...options, headers: { ...options.headers, origin: 'https://attacker.example' } })).status, 403);
    assert.equal((await request({ ...options, headers: { ...options.headers, 'x-web-login-csrf': 'forged' } })).status, 403);
    assert.equal((await request({ ...options, body: '{invalid' })).status, 400);
    assert.equal((await request({ ...options, body: JSON.stringify({ ...JSON.parse(options.body), apiKey: 'rejected' }) })).status, 422);
    assert.equal((await request(options)).status, 202);
    assert.deepEqual(Object.keys(forwarded).sort(), ['acknowledge', 'operation', 'providers', 'revision']);
    assert.deepEqual(forwarded.providers, [provider()]);
    const large = { ...provider(), models: Array.from({ length: 500 }, (_, i) => ({ id: 'model-' + i, name: 'Name'.repeat(30) })) };
    assert.equal((await request({ ...options, body: JSON.stringify({ revision: 'a'.repeat(64), acknowledge: true, providers: [large] }) })).status, 202);
    assert.equal((await request({ ...options, body: ' '.repeat(2 * 1024 * 1024 + 1) })).status, 413);
  } finally {
    store.close(); await gateway.close(); helper.closeAllConnections(); backend.closeAllConnections();
    await Promise.all([new Promise(done => helper.close(done)), new Promise(done => backend.close(done))]); f.close();
  }
});
