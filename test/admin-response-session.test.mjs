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

const apiKey = 'isolated-admin-response-private-provider-key';
const backendToken = 'isolated-admin-response-backend-session';

async function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'admin-response-session-'));
  const socket = join(directory, 'admin.sock');
  const calls = [], backendCalls = [];
  let holdResponse;
  const helperReceived = new Promise(resolve => { holdResponse = resolve; });
  const helper = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const data = JSON.parse(Buffer.concat(chunks).toString());
    calls.push(data);
    if (data.operation === 'provider-export') {
      // Receipt proves backend verification finished; leave the secret response pending.
      holdResponse(() => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 200, backup: {
          format: 'opencode-web-login-providers', version: 1,
          providers: [{ id: 'acme', name: 'Acme', baseURL: 'https://api.example.com/v1', apiKey, models: [{ id: 'coder', name: 'Coder' }] }],
        } }));
      });
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 200, available: true }));
  });
  const backend = http.createServer((req, res) => {
    backendCalls.push({ path: req.url, authorization: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'application/json' });
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
  const session = store.createSession(backendToken, origin);
  const cookie = `opencode_login_${port}=${session}`;
  const status = await fetch(origin + '/web-login/api/status', { headers: { cookie, 'x-opencode-login': '1' } });
  assert.equal(status.status, 200);
  const { csrf } = await status.json();
  assert.equal(typeof csrf, 'string');
  calls.length = 0;
  backendCalls.length = 0;
  const exportProviders = () => fetch(origin + '/web-login/api/provider-export', {
    method: 'POST', redirect: 'manual',
    headers: { cookie, origin, 'x-opencode-login': '1', 'x-web-login-csrf': csrf, 'content-type': 'application/json' },
    body: JSON.stringify({ includeSecrets: true }),
  });
  return { store, session, origin, cookie, calls, backendCalls, helperReceived, exportProviders };
}

async function assertRejected(response) {
  const text = await response.text();
  assert.deepEqual({ status: response.status, exposesKey: text.includes(apiKey), exposesToken: text.includes(backendToken) },
    { status: 401, exposesKey: false, exposesToken: false });
  const result = JSON.parse(text);
  assert.equal(result.loginRequired, true);
  assert.equal(result.backup, undefined);
}

for (const mode of ['logout', 'revokeAll and replace session']) {
  test(`provider-export withholds held helper secrets after ${mode}`, { timeout: 10000 }, async t => {
    const f = await fixture(t);
    const pending = f.exportProviders();
    const release = await f.helperReceived;
    try {
      assert.deepEqual(f.calls, [{ operation: 'provider-export', includeSecrets: true }]);
      assert.equal(f.backendCalls.length, 1);
      assert.equal(f.backendCalls[0].path, '/api/info');
      assert(f.backendCalls[0].authorization?.startsWith('Basic '));
      assert(f.store.session(f.session, f.origin));
      if (mode === 'logout') {
        const logout = await fetch(f.origin + '/logout', {
          method: 'POST', redirect: 'manual', headers: { cookie: f.cookie, origin: f.origin },
        });
        await logout.text();
        assert.equal(logout.status, 303);
        assert.equal(logout.headers.get('location'), '/login');
      } else {
        f.store.revokeAll();
        const replacement = f.store.createSession('isolated-replacement-backend-session', f.origin);
        assert.notEqual(replacement, f.session);
        assert(f.store.session(replacement, f.origin));
      }
      assert.equal(f.store.session(f.session, f.origin), undefined);
    } finally {
      release();
    }
    await assertRejected(await pending);
  });
}
