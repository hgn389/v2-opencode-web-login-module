import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeConfig } from '../config.mjs';

test('explicit HTTP IP origins support nginx port mapping without permitting plaintext domains', () => {
  assert.deepEqual(normalizeConfig({ publicOrigins: ['http://192.0.2.10:4096'] }).publicOrigins, ['http://192.0.2.10:4096']);
  for (const origin of ['http://example.com:4096', 'http://user@192.0.2.10:4096', 'http://192.0.2.10:4096/path', 'http://192.0.2.10:4096/']) {
    assert.throws(() => normalizeConfig({ publicOrigins: [origin] }));
  }
});
