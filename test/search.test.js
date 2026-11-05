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
  assert.deepEqual(Object.keys(response.body[0]).sort(), ['createdAt', 'filename', 'id', 'organizationId', 'ownerId']);
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

test('SQL injection is treated as filename data and cannot bypass access predicates', async () => {
  for (const payload of ["' OR 1=1 --", "x' OR 1=1 --", "' UNION SELECT id, organizationId, ownerId, filename, createdAt FROM documents --"]) {
    const response = await fixture.request(search(payload));
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, []);
  }
});

test('apostrophes and LIKE wildcards still work as ordinary filename searches', async () => {
  await fixture.db.query('UPDATE documents SET filename = $1 WHERE id = 1', ["Alice's notes.txt"]);
  for (const filename of ["Alice's", '%', '_', '']) {
    assert.deepEqual((await fixture.request(search(filename))).body.map(document => document.id), [1]);
  }
});

test('search keeps tenant, owner, manager, and explicit read permission rules', async () => {
  for (const [user, ids] of [['alice', [1]], ['bob', [1, 2]], ['adminA', []], ['charlie', [3]], ['diana', [3, 4]]]) {
    assert.deepEqual((await fixture.request(search(''), { user })).body.map(document => document.id), ids);
  }
  for (const permission of ['READ', 'WRITE', 'MANAGE']) {
    await fixture.repository.savePermission(2, 1, permission);
    assert.deepEqual((await fixture.request(search('bob'))).body.map(document => document.id), [2]);
  }
  await fixture.repository.savePermission(3, 1, 'MANAGE');
  assert.deepEqual((await fixture.request(search('charlie'))).body, []);
});
