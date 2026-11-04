import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { startFixture } from '../support/fixture.js';

let fixture;
beforeEach(async () => { fixture = await startFixture(); });
afterEach(async () => { await fixture?.close(); });

const search = filename => `/api/documents/search?filename=${encodeURIComponent(filename)}`;

test('normal filename searches respect the existing document access rules', async () => {
  const response = await fixture.request(search('alice'));
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(document => document.id), [1]);
  assert.equal(response.body[0].content, undefined);
  for (const filename of ['bob', 'charlie', 'missing']) {
    assert.deepEqual((await fixture.request(search(filename))).body, []);
  }
  assert.deepEqual((await fixture.request(search(''), { user: 'bob' })).body.map(document => document.id), [1, 2]);
  assert.deepEqual((await fixture.request(search(''), { user: 'adminA' })).body, []);
});

test('search requires a verified session', async () => {
  assert.equal((await fixture.request(search('alice'), { user: null })).status, 401);
  const login = await fixture.raw('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'alice-demo' } });
  assert.equal((await fixture.raw(search('alice'), { headers: { Authorization: `Bearer ${login.body.token}` } })).status, 403);
});

test('SQL injection bypasses the filename, tenant, and permission predicates', async () => {
  const response = await fixture.request(search("' OR 1=1 --"));
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(document => document.id), [1, 2, 3, 4]);
  assert.ok(response.body.some(document => document.organizationId === 2));
});
