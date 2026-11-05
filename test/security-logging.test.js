import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecurityLogger } from '../src/security-logging.js';
import { startFixture, totpCode } from '../support/fixture.js';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test('security JSON records authentication, denial and permission changes without sensitive values', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'vault-security-'));
  const path = join(directory, 'security.jsonl');
  const fixture = await startFixture({ logger: new SecurityLogger(path) });
  try {
    const pending = await fixture.raw('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'alice-demo' } });
    const pendingHeaders = { Authorization: `Bearer ${pending.body.token}` };
    const enrollment = await fixture.raw('/api/auth/enroll', { method: 'POST', headers: pendingHeaders });
    const invalid = await fixture.raw('/api/auth/verify', { method: 'POST', headers: pendingHeaders, body: { code: 'invalid-totp-marker' } });
    assert.equal(invalid.status, 401);
    const code = totpCode(enrollment.body.secret);
    const verified = await fixture.raw('/api/auth/verify', { method: 'POST', headers: pendingHeaders, body: { code } });
    assert.equal(verified.status, 200);
    const wrong = await fixture.raw('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'wrong-password-marker' } });
    assert.equal(wrong.status, 401);
    const headers = { Authorization: `Bearer ${verified.body.token}`, 'X-Request-Id': 'client-id-marker' };
    const own = await fixture.raw('/api/documents/1', { headers });
    assert.equal(own.status, 200);
    const denied = await fixture.raw('/api/documents/3?token=query-secret-marker', { headers });
    assert.equal(denied.status, 404);
    const forbidden = await fixture.raw('/api/documents/2/permissions', { method: 'PUT', headers, body: { userId: 1, permission: 'MANAGE' } });
    assert.equal(forbidden.status, 403);
    const changed = await fixture.raw('/api/documents/1/permissions', { method: 'PUT', headers, body: { userId: 6, permission: 'READ', password: 'body-secret-marker', content: own.body.content } });
    assert.equal(changed.status, 200);
    const text = readFileSync(path, 'utf8');
    const events = text.trim().split('\n').map(JSON.parse);
    assert.deepEqual(events.map(e => e.event), [
      'authentication.password_accepted', 'totp.failed', 'authentication.succeeded', 'authentication.failed',
      'document.access_denied', 'permission.modification_denied', 'permission.modified',
    ]);
    const responses = [pending, invalid, verified, wrong, denied, forbidden, changed];
    events.forEach((event, i) => {
      assert.match(event.requestId, uuid);
      assert.equal(event.requestId, responses[i].headers.get('x-request-id'));
      assert.equal(event.status, responses[i].status);
      assert.equal(new Date(event.timestamp).toISOString(), event.timestamp);
      assert.equal(event.userId, i === 3 ? null : 1);
      assert.equal(event.organizationId, i === 3 ? null : 1);
      assert.ok(Object.keys(event).every(key => ['timestamp', 'event', 'requestId', 'method', 'route', 'status', 'userId', 'organizationId', 'documentId', 'targetUserId', 'permission'].includes(key)));
    });
    assert.equal(new Set(events.map(e => e.requestId)).size, events.length);
    assert.equal(events[4].documentId, 3);
    assert.equal(events[4].route, '/api/documents/:id');
    assert.equal(events[6].targetUserId, 6);
    assert.equal(events[6].permission, 'READ');
    for (const secret of ['alice-demo', 'wrong-password-marker', 'invalid-totp-marker', 'body-secret-marker', 'query-secret-marker', 'client-id-marker', pending.body.token, verified.body.token, enrollment.body.secret, own.body.content]) {
      assert.ok(!text.includes(secret), `Excluded sensitive value: ${secret.slice(0, 8)}`);
    }
    assert.ok(!text.includes(JSON.stringify(code)));
    assert.ok(!Object.hasOwn(own.body, 'requestId'));
  } finally { await fixture.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('request IDs cover static, public, rejected and rate-limited requests and ignore client IDs', async () => {
  const events = [];
  const fixture = await startFixture({ logger: { write: event => events.push(event) } });
  try {
    const page = await fetch(fixture.base + '/', { headers: { 'X-Request-Id': 'chosen-by-client' } });
    await page.text();
    const ids = [page.headers.get('x-request-id')];
    for (let i = 0; i < 30; i++) {
      const response = await fixture.raw(i === 0 ? '/api/documents' : '/api/health');
      assert.equal(response.status, i === 0 ? 401 : 200);
      ids.push(response.headers.get('x-request-id'));
    }
    const blocked = await fixture.raw('/api/health');
    assert.equal(blocked.status, 429);
    ids.push(blocked.headers.get('x-request-id'));
    ids.forEach(id => assert.match(id, uuid));
    assert.equal(new Set(ids).size, ids.length);
    assert.deepEqual(events.map(e => e.event), ['document.access_denied', 'rate_limited']);
    assert.equal(events[1].requestId, blocked.headers.get('x-request-id'));
    assert.equal(events[1].status, 429);
    assert.equal(events[1].userId, null);
    assert.equal(events[1].organizationId, null);
  } finally { await fixture.close(); }
});

test('the dedicated destination accepts only the security field allowlist', () => {
  const directory = mkdtempSync(join(tmpdir(), 'vault-security-'));
  try {
    const path = join(directory, 'security.jsonl');
    new SecurityLogger(path).write({ event: 'test', password: 'hidden', token: 'hidden', totpSecret: 'hidden', content: 'hidden', headers: { authorization: 'hidden' } });
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), { event: 'test' });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
