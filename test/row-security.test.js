import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Pool, openDatabase } from '../src/database.js';
import { withOrganization } from '../src/organization-context.js';
import { createTestDatabase } from '../support/postgres.js';
import { startFixture, testEncryption } from '../support/fixture.js';

const ids = async db => (await db.query('SELECT id FROM documents ORDER BY id')).rows.map(row => row.id);

test('RLS filters raw document SQL for both SELECT accounts without application predicates', async () => {
  const database = await createTestDatabase(testEncryption);
  const url = new URL(database.url);
  url.username = 'vault_readonly';
  url.password = 'vault-readonly-demo';
  const readonly = new Pool({ connectionString: url.toString() });
  try {
    assert.deepEqual(await ids(database.owner), [1, 2, 3, 4]);
    for (const db of [database.runtime, readonly]) {
      assert.deepEqual(await ids(db), []);
      assert.deepEqual(await withOrganization(db, 1, ids), [1, 2]);
      assert.deepEqual(await withOrganization(db, 2, ids), [3, 4]);
      assert.deepEqual(await withOrganization(db, 999, ids), []);
      await withOrganization(db, 1, async client => {
        assert.equal((await client.query('SELECT * FROM documents WHERE "organizationId" = 2 OR id = 3')).rowCount, 0);
      });
    }
    await withOrganization(database.runtime, 1, async client => {
      assert.equal((await client.query('SELECT d.content, k."wrappedKey" FROM documents d JOIN document_keys k ON k."documentId" = d.id WHERE d.id = 3')).rowCount, 0);
    });
  } finally { await readonly.end(); await database.close(); }
});

test('organization context expires on commit and errors and stays separate across concurrent requests', async () => {
  const database = await createTestDatabase(testEncryption);
  const db = new Pool({ connectionString: database.url, max: 1 });
  try {
    assert.deepEqual(await withOrganization(db, 1, ids), [1, 2]);
    assert.deepEqual(await ids(db), []);
    assert.deepEqual(await withOrganization(db, 2, ids), [3, 4]);
    assert.deepEqual(await ids(db), []);
    await assert.rejects(withOrganization(db, 1, async () => { throw new Error('stop'); }), /stop/);
    assert.deepEqual(await ids(db), []);
    await assert.rejects(withOrganization(db, 2, client => client.query('SELECT 1 / 0')), { code: '22012' });
    assert.deepEqual(await ids(db), []);
    const organizations = [1, 2, 1, 2, 2, 1];
    const results = await Promise.all(organizations.map(org => withOrganization(database.runtime, org, ids)));
    assert.deepEqual(results, organizations.map(org => org === 1 ? [1, 2] : [3, 4]));
    assert.deepEqual(await ids(database.runtime), []);
  } finally { await db.end(); await database.close(); }
});

test('HTTP ignores supplied organization identifiers and preserves document permissions', async () => {
  const fixture = await startFixture();
  try {
    const spoof = { headers: { 'X-Organization-Id': '2', organizationId: '2' } };
    const listing = await fixture.request('/api/documents?organizationId=2', spoof);
    assert.equal(listing.status, 200);
    assert.deepEqual(listing.body.map(doc => doc.id), [1]);
    const search = await fixture.request('/api/documents/search?filename=charlie&organizationId=2', spoof);
    assert.deepEqual(search.body, []);
    assert.equal((await fixture.request('/api/documents/3?organizationId=2', spoof)).status, 404);
    assert.equal((await fixture.request('/api/documents/3/permissions', { ...spoof, method: 'PUT', body: { organizationId: 2, userId: 1, permission: 'READ' } })).status, 403);
    const own = await fixture.request('/api/documents/3', { user: 'charlie' });
    assert.equal(own.status, 200);
    assert.match(own.body.content, /Organization B/);
    assert.equal((await fixture.request('/api/documents/1', { user: 'charlie' })).status, 404);
    assert.equal((await fixture.request('/api/documents/2')).status, 404);
  } finally { await fixture.close(); }
});

test('startup still authenticates ciphertext in other organizations and organizations without users', async () => {
  const database = await createTestDatabase(testEncryption);
  try {
    await database.owner.query('UPDATE documents SET "authTag" = $1 WHERE id = 3', ['!']);
    await assert.rejects(openDatabase(database.url, testEncryption), /authentication failed/);
    await database.owner.query("INSERT INTO organizations VALUES (3, 'Empty organization')");
    await database.owner.query('UPDATE documents SET "organizationId" = 3 WHERE id = 3');
    await assert.rejects(openDatabase(database.url, testEncryption), /authentication failed/);
  } finally { await database.close(); }
});
