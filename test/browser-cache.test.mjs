import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { once } from 'node:events';
import { createLoginServer } from '../index.mjs';

test('offline worker is retired and explicit browser recovery preserves user storage', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'worker-retirement-'));
  const reserve = net.createServer().listen(0, '127.0.0.1'); await once(reserve, 'listening');
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const gateway = createLoginServer({ port, statePath: join(directory, 'state.sqlite') });
  try {
    await gateway.listen(); const origin = `http://127.0.0.1:${port}`;
    const worker = await fetch(origin + '/sw.js', { headers: { 'if-none-match': 'old-shell' } });
    assert.equal(worker.status, 200); assert.equal(worker.headers.get('cache-control'), 'no-store');
    const body = await worker.text(); assert(body.includes('skipWaiting')); assert(body.includes('clients.claim')); assert(body.includes('registration.unregister'));
    assert(!body.includes('caches.delete')); assert(!body.includes('navigate('));
    const page = await fetch(origin + '/api/web-login-browser-recovery'); assert.equal(page.status, 200);
    assert((await page.text()).includes('Save work'));
    const script = await (await fetch(origin + '/api/web-login-browser-recovery.js')).text();
    assert(script.includes("pathname==='/sw.js'")); assert(!script.includes('localStorage.clear')); assert(!script.includes('caches.delete'));
    assert.equal((await fetch(origin + '/api/info')).status, 401);
    assert.equal((await fetch(origin + '/sw.js', { method: 'POST' })).status, 405);
  } finally { await gateway.close(); rmSync(directory, { recursive: true, force: true }); }
});
