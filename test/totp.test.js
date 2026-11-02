import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startFixture, totpCode } from '../support/fixture.js';

test('pending sessions cannot read or change documents before TOTP verification', async () => {
  const fixture = await startFixture();
  try {
    const login = await fixture.raw('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'alice-demo' } });
    assert.equal(login.status, 200);
    assert.equal(login.body.state, 'pending');
    const headers = { Authorization: `Bearer ${login.body.token}` };
    for (const [method, path, body] of [
      ['GET', '/api/documents'], ['GET', '/api/documents/1'],
      ['GET', '/api/documents/1/permissions'],
      ['PUT', '/api/documents/1/permissions', { userId: 3, permission: 'MANAGE' }],
    ]) assert.equal((await fixture.raw(path, { method, body, headers })).status, 403);
    assert.equal(fixture.repository.findPermission(1, 3), undefined);

    const enrollment = await fixture.raw('/api/auth/enroll', { method: 'POST', headers });
    assert.equal(enrollment.status, 200);
    assert.match(enrollment.body.secret, /^[A-Z2-7]{32}$/);
    assert.match(enrollment.body.qrCode, /^data:image\/png;base64,/);
    assert.equal((await fixture.raw('/api/auth/verify', { method: 'POST', headers, body: { code: '000000x' } })).status, 401);
    assert.equal((await fixture.raw('/api/documents', { headers })).status, 403);

    const verified = await fixture.raw('/api/auth/verify', { method: 'POST', headers, body: { code: totpCode(enrollment.body.secret) } });
    assert.equal(verified.status, 200);
    assert.equal(verified.body.state, 'authenticated');
    assert.equal((await fixture.raw('/api/documents', { headers })).status, 401);
    const authenticated = { Authorization: `Bearer ${verified.body.token}` };
    assert.equal((await fixture.raw('/api/documents', { headers: authenticated })).status, 200);
    assert.equal((await fixture.raw('/api/auth/enroll', { method: 'POST', headers: authenticated })).status, 403);
    assert.equal((await fixture.raw('/api/auth/logout', { method: 'POST', headers: authenticated })).status, 204);
    assert.equal((await fixture.raw('/api/documents', { headers: authenticated })).status, 401);

    const second = await fixture.raw('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'alice-demo' } });
    assert.equal(second.body.enrollmentRequired, false);
    assert.equal((await fixture.raw('/api/auth/enroll', { method: 'POST', headers: { Authorization: `Bearer ${second.body.token}` } })).status, 409);
    assert.equal((await fixture.raw('/api/auth/verify', { method: 'POST', headers: { Authorization: `Bearer ${second.body.token}` }, body: { code: totpCode(enrollment.body.secret) } })).status, 200);
  } finally { await fixture.close(); }
});
