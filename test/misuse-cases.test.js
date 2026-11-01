import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { startFixture } from '../support/fixture.js';

let fixture;
beforeEach(async () => { fixture = await startFixture(); });
afterEach(async () => { await fixture?.close(); });

test('MC1: unauthorized document reads return 404 without leaking content', async () => {
  for (const id of [2, 3, 4]) {
    const response = await fixture.request(`/api/documents/${id}`);
    assert.equal(response.status, 404);
    assert.equal(response.body.detail, 'Document not found');
    assert.doesNotMatch(JSON.stringify(response.body), /CONFIDENTIAL|content|filename|organizationId/);
  }
  assert.deepEqual((await fixture.request('/api/documents')).body.map(document => document.id), [1]);
});

test('MC1: managers remain tenant-scoped and administrators have no implicit access', async () => {
  for (const [user, id] of [['bob', 3], ['diana', 1], ['charlie', 2], ['adminA', 1], ['alice', '003']]) {
    assert.equal((await fixture.request(`/api/documents/${id}`, { user })).status, 404);
  }
  fixture.repository.savePermission(3, 1, 'MANAGE');
  assert.equal((await fixture.request('/api/documents/3')).status, 404);
  for (const [user, id] of [['bob', 1], ['charlie', 3], ['diana', 3]]) {
    assert.equal((await fixture.request(`/api/documents/${id}`, { user })).status, 200);
  }
});

test('MC2: unauthorized self-grants return 403 and leave permissions unchanged', async () => {
  const path = '/api/documents/2/permissions';
  assert.equal(fixture.repository.findPermission(2, 1), undefined);
  assert.equal((await fixture.request(path)).status, 403);
  const response = await fixture.request(path, { method: 'PUT', body: { userId: 1, permission: 'MANAGE' } });
  assert.equal(response.status, 403);
  assert.equal(fixture.repository.findPermission(2, 1), undefined);
  const permissions = await fixture.request(path);
  assert.equal(permissions.status, 403);
  assert.deepEqual((await fixture.request('/api/documents')).body.map(document => document.id), [1]);
});

test('MC2: READ and WRITE cannot escalate or modify another user grant', async () => {
  const path = '/api/documents/2/permissions';
  for (const permission of ['READ', 'WRITE']) {
    fixture.repository.savePermission(2, 1, permission);
    for (const userId of [1, 2, 3, 4, 999]) {
      assert.equal((await fixture.request(path, { method: 'PUT', body: { userId, permission: 'MANAGE' } })).status, 403);
    }
    assert.equal(fixture.repository.findPermission(2, 1).permission, permission);
    assert.equal(fixture.repository.findPermission(2, 2).permission, 'MANAGE');
  }
});

test('MC2: missing documents, administrators, and foreign grants cannot bypass management', async () => {
  for (const user of ['alice', 'bob', 'adminA', 'charlie', 'diana']) {
    const path = '/api/documents/999/permissions';
    assert.equal((await fixture.request(path, { user })).status, 403);
    assert.equal((await fixture.request(path, { user, method: 'PUT', body: { userId: 1, permission: 'MANAGE' } })).status, 403);
  }
  assert.equal((await fixture.request('/api/documents/1/permissions', { user: 'adminA', method: 'PUT', body: { userId: 3, permission: 'MANAGE' } })).status, 403);
  fixture.repository.savePermission(3, 1, 'MANAGE');
  for (const method of ['GET', 'PUT']) {
    const response = await fixture.request('/api/documents/003/permissions', {
      method, ...(method === 'PUT' ? { body: { userId: 4, permission: 'READ' } } : {}),
    });
    assert.equal(response.status, 403);
  }
  assert.equal(fixture.repository.findPermission(3, 4).permission, 'MANAGE');
});
