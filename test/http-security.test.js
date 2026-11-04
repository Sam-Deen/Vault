import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { startFixture } from '../support/fixture.js';

let fixture;
beforeEach(async () => { fixture = await startFixture(); });
afterEach(async () => { await fixture?.close(); });

function checkHeaders(headers) {
  assert.match(headers.get('content-security-policy'), /script-src 'self'/);
  assert.match(headers.get('content-security-policy'), /img-src 'self' data:/);
  assert.match(headers.get('strict-transport-security'), /max-age=31536000/);
  assert.equal(headers.get('x-content-type-options'), 'nosniff');
  assert.equal(headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(headers.get('referrer-policy'), 'no-referrer');
  assert.equal(headers.get('x-powered-by'), null);
}

test('security headers cover successful API responses and validation/authentication errors', async () => {
  const health = await fixture.raw('/api/health');
  assert.equal(health.status, 200);
  checkHeaders(health.headers);
  const unauthorized = await fixture.raw('/api/documents');
  assert.equal(unauthorized.status, 401);
  checkHeaders(unauthorized.headers);
  const malformed = await fixture.raw('/api/auth/login', { method: 'POST', body: '{' });
  assert.equal(malformed.status, 400);
  checkHeaders(malformed.headers);
  assert.equal(malformed.body.detail, 'Malformed JSON');
});

test('the browser page and module script receive headers that permit local scripts and QR images', async () => {
  const page = await fetch(fixture.base + '/');
  assert.equal(page.status, 200);
  checkHeaders(page.headers);
  assert.match(await page.text(), /src="\/app.js"/);
  const script = await fetch(fixture.base + '/app.js');
  assert.equal(script.status, 200);
  checkHeaders(script.headers);
  assert.match(script.headers.get('content-type'), /javascript/);
  await script.text();
});

test('excessive login attempts return 429 with retry metadata and a safe JSON error', async () => {
  for (let i = 0; i < 30; i++) {
    const response = await fixture.raw('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'wrong-password' } });
    assert.equal(response.status, 401);
  }
  const blocked = await fixture.raw('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'wrong-password' } });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.title, 'Too Many Requests');
  assert.equal(blocked.body.detail, 'Too many requests; try again later');
  assert.match(blocked.headers.get('content-type'), /application\/problem\+json/);
  assert.ok(Number(blocked.headers.get('retry-after')) > 0);
  assert.ok(blocked.headers.get('ratelimit'));
  checkHeaders(blocked.headers);
  assert.doesNotMatch(JSON.stringify(blocked.body), /password|SELECT|stack|Error:/);
  assert.equal((await fixture.raw('/api/documents')).status, 429);
  assert.equal((await fixture.raw('/api/auth/verify', { method: 'POST', body: '{' })).status, 429);
  assert.equal((await fixture.raw('/api/health')).status, 429);
  assert.equal((await fixture.raw('/api/health', { headers: { 'X-Forwarded-For': '203.0.113.77' } })).status, 429);
  const page = await fetch(fixture.base + '/');
  assert.equal(page.status, 200);
  await page.text();
});

test('successful and failed API requests share the same limit', async () => {
  for (let i = 0; i < 30; i++) assert.equal((await fixture.raw('/api/health')).status, 200);
  assert.equal((await fixture.raw('/api/health')).status, 429);
  const login = await fixture.raw('/api/auth/login', { method: 'POST', body: { username: 'alice', password: 'alice-demo' } });
  assert.equal(login.status, 429);
});
