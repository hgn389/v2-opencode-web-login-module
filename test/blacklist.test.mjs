import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLoginServer } from '../index.mjs';
import { SecurityStore } from '../security.mjs';

function seed(store, ip, updated, blocked = 1, failures = blocked ? 10 : 3) {
  store.db.prepare('INSERT OR REPLACE INTO login_ips(ip, failures, blocked, updated) VALUES (?, ?, ?, ?)').run(ip, failures, blocked, updated);
}

test('SecurityStore blacklist paginates deterministically, searches literally and validates queries', () => {
  const directory = mkdtempSync(join(tmpdir(), 'blacklist-store-'));
  const store = new SecurityStore(join(directory, 'security.sqlite'));
  try {
    assert.deepEqual(store.blacklist(), { entries: [], total: 0, page: 1, pageSize: 50 });
    const expected = Array.from({ length: 53 }, (_, i) => ({ ip: `198.51.100.${String(i + 1).padStart(3, '0')}`, failures: 10, updated: 1000 + Math.floor(i / 2) }));
    for (const entry of expected) seed(store, entry.ip, entry.updated);
    seed(store, '2001:db8::ABCD', 2000);
    seed(store, '198.51.100.200', 3000, 0);
    expected.push({ ip: '2001:db8::ABCD', failures: 10, updated: 2000 });
    expected.sort((a, b) => b.updated - a.updated || a.ip.localeCompare(b.ip));
    const plain = result => ({ ...result, entries: result.entries.map(entry => ({ ...entry })) });
    assert.deepEqual(plain(store.blacklist()), { entries: expected.slice(0, 50), total: 54, page: 1, pageSize: 50 });
    assert.deepEqual(plain(store.blacklist(2)), { entries: expected.slice(50), total: 54, page: 2, pageSize: 50 });
    assert.deepEqual(plain(store.blacklist(999)), plain(store.blacklist(2)));
    assert.deepEqual(plain(store.blacklist(9, '  DB8::abcd  ')), { entries: [expected[0]], total: 1, page: 1, pageSize: 50 });
    assert.equal(store.blacklist(1, '198.51.100.0').total, 53);
    for (const search of ['%', '_', "' OR 1=1 --", 'no-match']) {
      assert.deepEqual(store.blacklist(9, search), { entries: [], total: 0, page: 1, pageSize: 50 });
    }
    for (const page of [0, -1, 1.5, NaN, Infinity, '1', Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => store.blacklist(page), /Invalid blacklist query/);
    for (const search of [null, 1, {}, 'x'.repeat(65)]) assert.throws(() => store.blacklist(1, search), /Invalid blacklist query/);
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('SecurityStore unblock rejects stale versions, clears failures and persists across reopening', () => {
  const directory = mkdtempSync(join(tmpdir(), 'blacklist-persist-'));
  const database = join(directory, 'security.sqlite');
  let store = new SecurityStore(database);
  try {
    seed(store, '198.51.100.10', 1000);
    seed(store, '2001:db8::20', 2000);
    seed(store, '198.51.100.30', 3000, 0);
    store.close();
    store = new SecurityStore(database);
    assert.equal(store.blacklist().total, 2, 'Blocks survive reopening');
    seed(store, '198.51.100.10', 1001);
    assert.equal(store.unblock('198.51.100.10', 1000), false);
    assert.deepEqual({ ...store.state('198.51.100.10') }, { failures: 10, blocked: 1 });
    assert.equal(store.unblock('198.51.100.30', 3000), false, 'Unblocking cannot clear a non-blocked failure row');
    assert.equal(store.state('198.51.100.30').failures, 3);
    assert.equal(store.unblock('198.51.100.99', 1001), false);
    assert.equal(store.unblock('198.51.100.10', 1001), true);
    assert.equal(store.unblock('198.51.100.10', 1001), false);
    assert.deepEqual(store.state('198.51.100.10'), { failures: 0, blocked: 0 });
    store.close();
    store = new SecurityStore(database);
    assert.deepEqual(store.state('198.51.100.10'), { failures: 0, blocked: 0 });
    assert.deepEqual(store.blacklist().entries.map(entry => entry.ip), ['2001:db8::20']);
    assert.equal(store.fail('198.51.100.10').failures, 1, 'A new failure starts at one after unblocking');
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

async function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'blacklist-http-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const token = 'isolated-blacklist-native-token';
  const authorization = 'Basic ' + Buffer.from('opencode:' + token).toString('base64');
  const checks = [];
  let authorized = true;
  const backend = http.createServer((req, res) => {
    checks.push({ path: req.url, authorization: req.headers.authorization });
    res.writeHead(authorized && req.url === '/api/info' && req.headers.authorization === authorization ? 200 : 401, { 'content-type': 'application/json' });
    res.end('{"version":"2.0.1"}');
  });
  backend.listen(0, '127.0.0.1');
  await once(backend, 'listening');
  t.after(async () => { backend.closeAllConnections(); await new Promise(resolve => backend.close(resolve)); });
  const reserve = http.createServer();
  reserve.listen(0, '127.0.0.1');
  await once(reserve, 'listening');
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const database = join(directory, 'security.sqlite');
  // Like the provider API tests, seed a real persisted session without an admin helper.
  const gateway = createLoginServer({ port, backendPort: backend.address().port, statePath: database });
  t.after(() => gateway.close());
  const store = new SecurityStore(database);
  t.after(() => store.close());
  const session = store.createSession(token, origin);
  const cookie = `opencode_login_${port}=${session}`;
  await gateway.listen();
  const request = (path, options = {}) => fetch(origin + '/web-login/' + path, {
    ...options, headers: { cookie, 'x-opencode-login': '1', ...options.headers },
  });
  const post = (csrf, fields, headers = {}) => request('api/blacklist-unblock', {
    method: 'POST', headers: { origin, 'content-type': 'application/json', 'x-web-login-csrf': csrf, ...headers }, body: JSON.stringify(fields),
  });
  return { origin, store, session, request, post, checks, authorization, revokeCredential: () => { authorized = false; } };
}

test('blacklist HTTP API authenticates, validates queries and protects unblock with origin and session-bound CSRF', async t => {
  const f = await fixture(t);
  const entry = { ip: '198.51.100.10', updated: 1000 };
  seed(f.store, entry.ip, entry.updated);
  seed(f.store, '2001:db8::20', 2000);
  assert.equal((await f.request('api/blacklist-status', { headers: { cookie: '' } })).status, 401);
  assert.equal((await f.post('forged', entry, { cookie: '' })).status, 401);
  for (const headers of [{ 'x-opencode-login': '' }, { origin: 'https://attacker.invalid' }, { 'sec-fetch-site': 'cross-site' }]) {
    assert.equal((await f.request('api/blacklist-status', { headers })).status, 403);
  }
  const response = await f.request('api/blacklist-status?page=99&search=198.51.100');
  assert.equal(response.status, 200, 'Blacklist is available without adminSocket');
  const status = await response.json();
  assert.deepEqual(status.entries, [{ ...entry, failures: 10, country: null }]);
  assert.equal(status.total, 1);
  assert.equal(status.page, 1);
  assert.equal(status.pageSize, 50);
  assert.equal(status.available, true);
  assert.match(status.csrf, /^\d{13}\.[a-f0-9]{48}\.[a-f0-9]{64}$/);
  for (const query of ['page=0', 'page=-1', 'page=1.5', 'page=NaN', 'page=9007199254740992', 'search=' + 'x'.repeat(65)]) {
    assert.equal((await f.request('api/blacklist-status?' + query)).status, 400);
  }
  assert.equal((await f.request('api/blacklist-status', { method: 'POST' })).status, 405);
  const before = f.checks.length;
  for (const headers of [
    { 'x-web-login-csrf': '' }, { 'x-web-login-csrf': 'forged' },
    { origin: '' }, { origin: 'https://attacker.invalid' },
    { 'sec-fetch-site': 'cross-site' }, { 'x-opencode-login': '' },
    { 'content-type': 'text/plain' },
    { cookie: `opencode_login_${new URL(f.origin).port}=${f.store.createSession('another-native-token', f.origin)}` },
  ]) assert.equal((await f.post(status.csrf, entry, headers)).status, 403);
  assert.equal(f.checks.length, before, 'Rejected CSRF/origin requests never reauthenticate');
  assert.equal(f.store.state(entry.ip).blocked, 1);
  for (const fields of [
    { ...entry, ip: 'not-an-ip' }, { ...entry, ip: '198.51.100.999' },
    { ...entry, ip: '127.0.0.1/8' }, { ...entry, ip: 123 },
    { ...entry, updated: '1000' }, { ...entry, updated: -1 },
    { ...entry, updated: 1.5 }, { ...entry, updated: Number.MAX_SAFE_INTEGER + 1 },
    { ip: entry.ip }, { ...entry, command: 'arbitrary' },
  ]) assert.equal((await f.post(status.csrf, fields)).status, 400);
  assert.equal(f.store.state(entry.ip).blocked, 1);
  assert.equal((await f.post(status.csrf, { ...entry, updated: 999 })).status, 409);
  assert.equal(f.store.state(entry.ip).blocked, 1);
  const checksBeforeUnblock = f.checks.length;
  const removed = await f.post(status.csrf, entry);
  assert.equal(removed.status, 200, 'Unblocking requires no adminSocket');
  assert.deepEqual(await removed.json(), { removed: true });
  assert.deepEqual(f.checks.slice(checksBeforeUnblock), [{ path: '/api/info', authorization: f.authorization }], 'Unblock reauthenticates the session credential against the backend');
  assert.deepEqual(f.store.state(entry.ip), { failures: 0, blocked: 0 });
  assert.equal((await f.post(status.csrf, entry)).status, 409);
  const remaining = await (await f.request('api/blacklist-status')).json();
  assert.deepEqual(remaining.entries.map(row => row.ip), ['2001:db8::20']);
  assert.equal(remaining.total, 1);
});

test('blacklist unblock refuses a revoked backend credential and revokes the local session', async t => {
  const f = await fixture(t);
  const entry = { ip: '2001:db8::10', updated: 1000 };
  seed(f.store, entry.ip, entry.updated);
  const { csrf } = await (await f.request('api/blacklist-status')).json();
  f.revokeCredential();
  const before = f.checks.length;
  const response = await f.post(csrf, entry);
  assert.equal(response.status, 401);
  assert.equal((await response.json()).loginRequired, true);
  assert.deepEqual(f.checks.slice(before), [{ path: '/api/info', authorization: f.authorization }]);
  assert.equal(f.store.session(f.session, f.origin, false), undefined);
  assert.deepEqual({ ...f.store.state(entry.ip) }, { failures: 10, blocked: 1 });
  assert.equal((await f.request('api/blacklist-status')).status, 401);
  assert.equal((await f.post(csrf, entry)).status, 401);
  assert.equal(f.checks.length, before + 1, 'A revoked local session cannot trigger further backend checks');
});

test('embedded admin HTML includes its initial-paint marker server-side and standalone HTML does not', async t => {
  const f = await fixture(t);
  for (const page of ['blacklist', 'password', 'updates', 'opencode', 'providers']) {
    const embedded = await f.request(page + '?embedded=1');
    assert.equal(embedded.status, 200);
    assert.match(embedded.headers.get('content-type'), /text\/html/);
    assert.match(await embedded.text(), /<[^>]+\bdata-web-login-page\b[^>]*\bdata-embedded(?:\s|>|=)/, 'The raw HTML must carry the marker before client JavaScript runs');
    for (const query of ['', '?embedded=0']) {
      const standalone = await f.request(page + query);
      assert.equal(standalone.status, 200);
      const html = await standalone.text();
      assert.match(html, /<[^>]+\bdata-web-login-page\b/);
      assert.doesNotMatch(html, /<[^>]+\bdata-embedded(?:\s|>|=)/);
    }
  }
});
