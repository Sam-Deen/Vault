import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { startFixture } from '../support/fixture.js';

let fixture;
beforeEach(async () => { fixture = await startFixture(); });
afterEach(async () => { await fixture?.close(); });

test('MC1: Alice can retrieve unauthorized documents by changing the ID', async () => {
  for (const id of [2, 3, 4]) {
    const response = await fixture.request(`/api/documents/${id}`);
    assert.equal(response.status, 200);
    assert.equal(response.body.id, id);
    assert.ok(response.body.content);
  }
  assert.deepEqual((await fixture.request('/api/documents')).body.map(document => document.id), [1]);
});

test('MC2: Alice can grant herself MANAGE despite the initial management denial', async () => {
  const path = '/api/documents/2/permissions';
  assert.equal(fixture.repository.findPermission(2, 1), undefined);
  assert.equal((await fixture.request(path)).status, 403);
  const response = await fixture.request(path, { method: 'PUT', body: { userId: 1, permission: 'MANAGE' } });
  assert.equal(response.status, 200);
  assert.equal(response.body.permission, 'MANAGE');
  assert.equal(fixture.repository.findPermission(2, 1).permission, 'MANAGE');
  const permissions = await fixture.request(path);
  assert.equal(permissions.status, 200);
  assert.deepEqual(permissions.body.map(permission => permission.userId), [1, 2]);
  assert.deepEqual((await fixture.request('/api/documents')).body.map(document => document.id), [1, 2]);
});
