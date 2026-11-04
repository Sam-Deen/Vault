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
