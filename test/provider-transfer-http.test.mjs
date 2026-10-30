import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLoginServer } from '../index.mjs';
import { SecurityStore } from '../security.mjs';

const apiKey = 'isolated-transfer-http-private-api-key';
const provider = () => ({ id: 'acme', name: 'Acme', baseURL: 'https://api.example.com/v1', apiKey, models: [{ id: 'coder', name: 'Coder' }] });
const importFields = () => ({ revision: 'a'.repeat(64), acknowledge: true, providers: [provider()] });

async function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'provider-transfer-http-'));
  const socket = join(directory, 'admin.sock');
  const calls = [], backendCalls = [];
  let backendStatus = 200;
  let exportedProviders;
  const helper = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const data = JSON.parse(Buffer.concat(chunks).toString());
    calls.push(data);
    let result = { status: 200, available: true };
    if (data.operation === 'provider-export') {
      const exported = provider();
      if (!data.includeSecrets) delete exported.apiKey;
      result = { status: 200, backup: { format: 'opencode-web-login-providers', version: 1, providers: exportedProviders ?? [exported] } };
    } else if (data.operation === 'provider-import') {
      result = { status: 202, message: 'Fixture import accepted' };
    }
    res.writeHead(result.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(result));
  });
  const backend = http.createServer((req, res) => {
    backendCalls.push({ path: req.url, authorization: req.headers.authorization });
    res.writeHead(backendStatus, { 'content-type': 'application/json' });
    res.end('{}');
  });
  helper.listen(socket);
  backend.listen(0, '127.0.0.1');
  await Promise.all([once(helper, 'listening'), once(backend, 'listening')]);
  const reserve = net.createServer();
  reserve.listen(0, '127.0.0.1');
  await once(reserve, 'listening');
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const database = join(directory, 'state.sqlite');
  const gateway = createLoginServer({ port, backendPort: backend.address().port, statePath: database, adminSocket: socket });
  const store = new SecurityStore(database);
  await gateway.listen();
  t.after(async () => {
    store.close();
    await gateway.close();
    helper.closeAllConnections();
    backend.closeAllConnections();
    await Promise.all([new Promise(resolve => helper.close(resolve)), new Promise(resolve => backend.close(resolve))]);
    rmSync(directory, { recursive: true, force: true });
  });
  const session = store.createSession('isolated-provider-transfer-backend-session', origin);
  const cookie = `opencode_login_${port}=${session}`;
  const statusResponse = await fetch(origin + '/web-login/api/status', { headers: { cookie, 'x-opencode-login': '1' } });
  assert.equal(statusResponse.status, 200);
  const { csrf } = await statusResponse.json();
  assert.equal(typeof csrf, 'string');
  calls.length = 0;
  const post = (operation, fields, headers = {}) => fetch(origin + '/web-login/api/' + operation, {
    method: 'POST', redirect: 'manual',
    headers: { cookie, origin, 'x-opencode-login': '1', 'x-web-login-csrf': csrf, 'content-type': 'application/json', ...headers },
    body: JSON.stringify(fields),
  });
  return { calls, backendCalls, post, store, session, origin,
    setBackendStatus: value => { backendStatus = value; },
    setExportedProviders: value => { exportedProviders = value; },
  };
}

test('provider transfer HTTP forwards explicit export secret consent and import keys with exact operation payloads', async t => {
  const f = await fixture(t);
  for (const includeSecrets of [false, true]) {
    const response = await f.post('provider-export', { includeSecrets });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.status, 200);
    assert.equal(result.backup.format, 'opencode-web-login-providers');
    assert.equal(result.backup.version, 1);
    assert.equal(result.backup.providers[0].apiKey, includeSecrets ? apiKey : undefined);
    assert.deepEqual(f.calls.at(-1), { operation: 'provider-export', includeSecrets });
  }
  const fields = importFields();
  const imported = await f.post('provider-import', fields);
  assert.equal(imported.status, 202);
  assert.equal((await imported.json()).status, 202);
  assert.deepEqual(f.calls.at(-1), { operation: 'provider-import', ...fields });
  assert.equal(f.backendCalls.length, 3);
  for (const request of f.backendCalls) {
    assert.equal(request.path, '/api/info');
    assert(request.authorization?.startsWith('Basic '));
  }
});

test('provider transfer HTTP rejects unauthenticated, cross-origin and forged CSRF requests without leaking keys or forwarding', async t => {
  const f = await fixture(t);
  for (const [operation, fields] of [['provider-export', { includeSecrets: true }], ['provider-import', importFields()]]) {
    for (const [headers, expected] of [
      [{ cookie: '' }, 401],
      [{ origin: 'https://attacker.example' }, 403],
      [{ origin: '' }, 403],
      [{ 'x-web-login-csrf': 'forged' }, 403],
      [{ 'x-web-login-csrf': '' }, 403],
      [{ 'x-opencode-login': '' }, 403],
    ]) {
      const response = await f.post(operation, fields, headers);
      assert.equal(response.status, expected, `${operation} ${JSON.stringify(headers)}`);
      const text = await response.text();
      assert(!text.includes(apiKey));
      assert(!text.includes('isolated-provider-transfer-backend-session'));
    }
  }
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.backendCalls, []);
});

test('provider transfer HTTP rejects backend-revoked sessions before forwarding to the admin socket', async t => {
  for (const operation of ['provider-export', 'provider-import']) {
    const f = await fixture(t);
    f.store.fail('127.0.0.1');
    f.setBackendStatus(401);
    const response = await f.post(operation, operation === 'provider-export' ? { includeSecrets: true } : importFields());
    assert.equal(response.status, 401);
    const result = await response.json();
    assert.equal(result.loginRequired, true);
    assert(!JSON.stringify(result).includes(apiKey));
    assert.deepEqual(f.calls, []);
    assert.equal(f.backendCalls.length, 1);
    assert.equal(f.store.session(f.session, f.origin), undefined);
    assert.equal(f.store.state('127.0.0.1').failures, 1);
  }
});

test('provider transfer HTTP rejects imports above 2 MiB before backend verification or admin forwarding', async t => {
  const f = await fixture(t);
  const fields = importFields();
  fields.providers[0].name = 'x'.repeat(2 * 1024 * 1024);
  assert(Buffer.byteLength(JSON.stringify(fields)) > 2 * 1024 * 1024);
  const response = await f.post('provider-import', fields);
  assert.equal(response.status, 413);
  assert(!(await response.text()).includes(apiKey));
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.backendCalls, []);
});

test('provider transfer HTTP never forwards injected administrative fields to the admin socket', async t => {
  const f = await fixture(t);
  for (const [operation, fields] of [['provider-export', { includeSecrets: false }], ['provider-import', importFields()]]) {
    const before = f.calls.length;
    const injected = { ...fields, operation: 'password', newPassword: 'injected-password', confirmPassword: 'injected-password', automatic: true, channel: 'beta', version: '999.0.0', command: '/bin/sh' };
    const response = await f.post(operation, injected);
    await response.text();
    if ([400, 422].includes(response.status)) {
      assert.equal(f.calls.length, before);
    } else {
      assert.equal(response.status, operation === 'provider-export' ? 200 : 202);
      assert.equal(f.calls.length, before + 1);
      assert.deepEqual(f.calls.at(-1), { operation, ...fields });
    }
  }
});

test('provider transfer HTTP reads an export backup larger than the former 64 KiB admin response limit', async t => {
  const f = await fixture(t);
  const providers = Array.from({ length: 100 }, (_, index) => ({ ...provider(), id: `provider${index}`, models: Array.from({ length: 20 }, (__, model) => ({ id: `model-${model}`, name: `Model ${model} ${'x'.repeat(50)}` })) }));
  f.setExportedProviders(providers);
  const expected = { status: 200, backup: { format: 'opencode-web-login-providers', version: 1, providers } };
  const size = Buffer.byteLength(JSON.stringify(expected));
  assert(size > 65536);
  assert(size < 2 * 1024 * 1024);
  const response = await f.post('provider-export', { includeSecrets: true });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), expected);
  assert.deepEqual(f.calls, [{ operation: 'provider-export', includeSecrets: true }]);
});
