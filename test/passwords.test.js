import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startFixture } from '../support/fixture.js';
import { verifyPassword } from '../src/passwords.js';

test('two seeded users with the same password have different stored Argon2id hashes and salts', async () => {
  const fixture = await startFixture();
  try {
    const first = (await fixture.repository.findUserByUsername('hashAlice')).passwordHash;
    const second = (await fixture.repository.findUserByUsername('hashBob')).passwordHash;
    assert.notEqual(first, second);
    assert.notEqual(first.split('$')[4], second.split('$')[4]);
    for (const hash of [first, second]) {
      assert.match(hash, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
      assert.equal(verifyPassword('shared-demo', hash), true);
      assert.equal(verifyPassword('wrong-password', hash), false);
    }
  } finally { await fixture.close(); }
});

test('both demo users reject incorrect passwords and authenticate with the correct password and TOTP', async () => {
  const fixture = await startFixture();
  try {
    for (const username of ['hashAlice', 'hashBob']) {
      const rejected = await fixture.raw('/api/auth/login', {
        method: 'POST', body: { username, password: 'wrong-password' },
      });
      assert.equal(rejected.status, 401);
      assert.equal(rejected.body.detail, 'Invalid credentials');
      assert.equal(rejected.body.token, undefined);

      const pending = await fixture.raw('/api/auth/login', {
        method: 'POST', body: { username, password: 'shared-demo' },
      });
      assert.equal(pending.status, 200);
      assert.equal(pending.body.state, 'pending');
      assert.equal((await fixture.raw('/api/documents', {
        headers: { Authorization: `Bearer ${pending.body.token}` },
      })).status, 403);

      const authenticated = await fixture.login(username, 'shared-demo');
      assert.equal(authenticated.status, 200);
      assert.equal(authenticated.body.state, 'authenticated');
      const documents = await fixture.raw('/api/documents', {
        headers: { Authorization: `Bearer ${authenticated.body.token}` },
      });
      assert.equal(documents.status, 200);
      assert.deepEqual(documents.body, []);
    }
  } finally { await fixture.close(); }
});
