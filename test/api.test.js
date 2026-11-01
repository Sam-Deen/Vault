import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startFixture } from '../support/fixture.js';
import { openDatabase } from '../src/database.js';
import { VaultRepository } from '../src/repository.js';
import { verifyPassword } from '../src/passwords.js';

let fixture;
beforeEach(async () => { fixture = await startFixture(); });
afterEach(async () => { await fixture?.close(); });

const permissionPath = '/api/documents/2/permissions';
const grant = (userId = 1, permission = 'MANAGE') => ({ userId, permission });

test('health is public and returns the original response', async () => {
  const response = await fixture.request('/api/health', { user: null });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { status: 'UP' });
});

test('every document endpoint requires Basic authentication', async () => {
  for (const [method, path] of [
    ['GET', '/api/documents'], ['GET', '/api/documents/1'],
    ['GET', permissionPath], ['PUT', permissionPath],
  ]) {
    const response = await fixture.request(path, { user: null, method, ...(method === 'PUT' ? { body: grant() } : {}) });
    assert.equal(response.status, 401);
    assert.match(response.headers.get('www-authenticate'), /^Basic/);
  }
});

test('invalid credentials and malformed Basic headers fail', async () => {
  for (const options of [
    { password: 'wrong' }, { user: 'missing' },
    { headers: { Authorization: 'Bearer alice' } },
    { headers: { Authorization: 'Basic YWxpY2U=' } },
    { headers: { Authorization: 'Basic !!!' } },
    { user: "alice' OR 1=1 --" },
  ]) assert.equal((await fixture.request('/api/documents', options)).status, 401);
});

test('all five accounts keep their original authorized document lists', async () => {
  for (const [user, ids] of [
    ['alice', [1]], ['bob', [1, 2]], ['adminA', []], ['charlie', [3]], ['diana', [3, 4]],
  ]) {
    const response = await fixture.request('/api/documents', { user });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.map(document => document.id), ids);
    for (const document of response.body) {
      assert.deepEqual(Object.keys(document).sort(), ['createdAt', 'filename', 'id', 'organizationId', 'ownerId']);
    }
  }
});

test('owned document preserves every original JSON field and value', async () => {
  const response = await fixture.request('/api/documents/1');
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    id: 1, organizationId: 1, ownerId: 1, filename: 'alice-notes.txt',
    content: "Alice's private notes from Organization A.", createdAt: '2026-01-01T12:00:00Z',
  });
});

test('permission reading enforces organization and management authorization', async () => {
  for (const [user, id] of [['alice', 2], ['alice', 3], ['bob', 3], ['charlie', 1], ['diana', 2], ['adminA', 1]]) {
    assert.equal((await fixture.request(`/api/documents/${id}/permissions`, { user })).status, 403);
  }
  const response = await fixture.request(permissionPath, { user: 'bob' });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, [{ id: 2, documentId: 2, userId: 2, permission: 'MANAGE' }]);
});

test('authorized grants and updates retain the same row and do not create duplicates', async () => {
  const first = await fixture.request(permissionPath, { user: 'bob', method: 'PUT', body: grant(1, 'READ') });
  const second = await fixture.request(permissionPath, { user: 'bob', method: 'PUT', body: grant(1, 'WRITE') });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.deepEqual(second.body, { id: first.body.id, documentId: 2, userId: 1, permission: 'WRITE' });
  assert.equal(fixture.repository.listPermissions(2).length, 2);
  assert.deepEqual((await fixture.request('/api/documents')).body.map(document => document.id), [1, 2]);
});

test('owners and workspace managers do not need an explicit grant', async () => {
  fixture.db.exec('DELETE FROM permissions WHERE documentId = 1');
  for (const user of ['alice', 'bob']) {
    assert.equal((await fixture.request('/api/documents/1/permissions', { user })).status, 200);
    assert.equal((await fixture.request('/api/documents/1/permissions', { user, method: 'PUT', body: grant(3, 'READ') })).status, 200);
  }
  assert.equal((await fixture.request('/api/documents/3/permissions', { user: 'diana', method: 'PUT', body: grant(5, 'WRITE') })).status, 200);
});

test('READ and WRITE allow reads and listing but not permission reading', async () => {
  for (const permission of ['READ', 'WRITE']) {
    await fixture.request(permissionPath, { user: 'bob', method: 'PUT', body: grant(1, permission) });
    assert.equal((await fixture.request('/api/documents/2')).status, 200);
    assert.equal((await fixture.request('/api/documents')).body.length, 2);
    assert.equal((await fixture.request(permissionPath)).status, 403);
  }
});

test('explicit MANAGE permits granting another same-organization user access', async () => {
  await fixture.request(permissionPath, { user: 'bob', method: 'PUT', body: grant() });
  assert.equal((await fixture.request(permissionPath, { method: 'PUT', body: grant(3, 'READ') })).status, 200);
  assert.deepEqual((await fixture.request('/api/documents', { user: 'adminA' })).body.map(document => document.id), [2]);
});

test('requester and recipient organization boundaries reject writes without side effects', async () => {
  assert.equal((await fixture.request('/api/documents/3/permissions', { method: 'PUT', body: grant(4, 'READ') })).status, 403);
  assert.equal(fixture.repository.findPermission(3, 4).permission, 'MANAGE');
  assert.equal((await fixture.request(permissionPath, { user: 'bob', method: 'PUT', body: grant(4) })).status, 400);
  assert.equal(fixture.repository.findPermission(2, 4), undefined);
  assert.equal((await fixture.request(permissionPath, { user: 'bob', method: 'PUT', body: grant(999) })).status, 404);
});

test('invalid permission bodies return 400 without writing', async () => {
  for (const body of [
    {}, { userId: 1 }, { permission: 'READ' }, null, [],
    grant(0), grant(-1), grant(1.5), grant('1'), grant(Number.MAX_SAFE_INTEGER + 1),
    grant(1, 'OWNER'), grant(1, null), grant(1, 0), grant(1, 2), grant(1, 'read'),
    grant("1 OR 1=1"), '{',
  ]) {
    const response = await fixture.request(permissionPath, { method: 'PUT', body });
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.equal(fixture.repository.findPermission(2, 1), undefined);
    assert.doesNotMatch(JSON.stringify(response.body), /SELECT|INSERT|SyntaxError|passwordHash/);
  }
});

test('non-JSON PUT is rejected and malformed route IDs cannot reach SQL', async () => {
  const response = await fixture.request(permissionPath, {
    method: 'PUT', body: 'userId=1&permission=MANAGE',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(response.status, 415);
  for (const id of ['abc', '1.5', '9007199254740992', encodeURIComponent('1 OR 1=1')]) {
    assert.equal((await fixture.request(`/api/documents/${id}`)).status, 400);
  }
  assert.equal((await fixture.request('/api/documents/999')).status, 404);
  assert.equal((await fixture.request('/api/documents/-1')).status, 404);
});

test('SQLite restart preserves grants and seed data without duplication', () => {
  const directory = mkdtempSync(join(tmpdir(), 'vault-test-'));
  const path = join(directory, 'vault.sqlite');
  let db;
  try {
    db = openDatabase(path);
    let repository = new VaultRepository(db);
    const saved = repository.savePermission(2, 1, 'WRITE');
    repository.savePermission(1, 2, 'READ');
    const storedPassword = repository.findUser(1).passwordHash;
    assert.notEqual(storedPassword, 'alice-demo');
    assert.equal(verifyPassword('alice-demo', storedPassword), true);
    db.close();
    db = openDatabase(path);
    repository = new VaultRepository(db);
    assert.deepEqual(repository.findPermission(2, 1), saved);
    assert.equal(repository.findPermission(1, 2).permission, 'READ');
    assert.equal(repository.findUser(1).passwordHash, storedPassword);
    for (const [table, count] of [['organizations', 2], ['users', 5], ['documents', 4], ['permissions', 7]]) {
      assert.equal(db.prepare(`SELECT count(*) AS count FROM ${table}`).get().count, count);
    }
  } finally {
    db?.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
