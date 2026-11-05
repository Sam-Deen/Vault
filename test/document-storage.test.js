import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import { spawnSync } from 'node:child_process';
import { DocumentEncryption } from '../src/document-encryption.js';
import { openDatabase } from '../src/database.js';
import { VaultRepository } from '../src/repository.js';
import { createTestDatabase } from '../support/postgres.js';
import { startFixture } from '../support/fixture.js';

const encryption = new DocumentEncryption(randomBytes(32).toString('hex'));
async function storedRows(db) {
  return {
    documents: (await db.query('SELECT * FROM documents ORDER BY id')).rows,
    keys: (await db.query('SELECT * FROM document_keys ORDER BY "documentId", version')).rows,
  };
}

test('PostgreSQL stores ciphertext and wrapped keys, and a new version rotates both', async () => {
  const database = await createTestDatabase(encryption);
  try {
    const repository = new VaultRepository(database.owner, encryption);
    const first = await storedRows(database.owner);
    assert.equal(first.documents.length, 4);
    assert.equal(first.keys.length, 4);
    for (const document of first.documents) {
      assert.equal(document.version, 1);
      assert.notEqual(document.content, await repository.readDocumentContent(document.id));
      assert.doesNotMatch(document.content, /CONFIDENTIAL|private notes/);
    }
    const original = await repository.readDocumentContent(1);
    assert.equal(await repository.saveDocumentVersion(1, original), 2);
    assert.equal(await repository.readDocumentContent(1), original);
    const second = await storedRows(database.owner);
    assert.equal(second.documents[0].version, 2);
    for (const field of ['content', 'iv', 'authTag']) assert.notEqual(first.documents[0][field], second.documents[0][field]);
    for (const field of ['wrappedKey', 'iv', 'authTag']) assert.notEqual(first.keys[0][field], second.keys[0][field]);
    assert.equal(second.keys.length, 4);
    assert.equal(second.keys[0].version, 2);
  } finally { await database.close(); }
});

test('wrong master keys and damaged versions fail startup without changing stored records', async () => {
  const database = await createTestDatabase(encryption);
  try {
    const stored = await storedRows(database.owner);
    await assert.rejects(openDatabase(database.url, new DocumentEncryption(randomBytes(32).toString('hex'))), /authentication failed/);
    assert.deepEqual(await storedRows(database.owner), stored);
    await database.owner.query('UPDATE documents SET version = 0 WHERE id = 1');
    const damaged = await storedRows(database.owner);
    await assert.rejects(openDatabase(database.url, encryption), /authentication failed/);
    assert.deepEqual(await storedRows(database.owner), damaged);
  } finally { await database.close(); }
});

test('a failed encrypted version write rolls back the content and key together', async () => {
  const database = await createTestDatabase(encryption);
  try {
    const before = await storedRows(database.owner);
    await database.owner.query('ALTER TABLE document_keys ADD CONSTRAINT test_version CHECK (version = 1)');
    const repository = new VaultRepository(database.owner, encryption);
    await assert.rejects(repository.saveDocumentVersion(1, 'Replacement'), { code: '23514' });
    assert.deepEqual(await storedRows(database.owner), before);
  } finally { await database.close(); }
});

test('missing master configuration fails before connecting to the database', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', "import { openDatabase } from './src/database.js'; await openDatabase();"], {
    cwd: fileURLToPath(new URL('..', import.meta.url)), env: { ...process.env, DOCUMENT_MASTER_KEY: '' }, encoding: 'utf8',
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /DOCUMENT_MASTER_KEY/);
});

test('keygen preserves an existing master key and other environment settings', () => {
  const directory = mkdtempSync(join(tmpdir(), 'vault-key-test-'));
  try {
    const envPath = join(directory, '.env');
    const script = fileURLToPath(new URL('../scripts/generate-master-key.js', import.meta.url));
    const env = { ...process.env };
    delete env.DOCUMENT_MASTER_KEY;
    writeFileSync(envPath, 'SERVER_PORT=9090\nDOCUMENT_MASTER_KEY=\n');
    for (let i = 0; i < 2; i++) {
      const before = readFileSync(envPath, 'utf8');
      const result = spawnSync(process.execPath, [script], { cwd: directory, env, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      const after = readFileSync(envPath, 'utf8');
      assert.equal(parseEnv(after).SERVER_PORT, '9090');
      assert.match(parseEnv(after).DOCUMENT_MASTER_KEY, /^[0-9a-f]{64}$/);
      if (i === 1) assert.equal(after, before);
    }
    writeFileSync(envPath, 'DOCUMENT_MASTER_KEY=invalid\n');
    assert.notEqual(spawnSync(process.execPath, [script], { cwd: directory, env }).status, 0);
    assert.equal(readFileSync(envPath, 'utf8'), 'DOCUMENT_MASTER_KEY=invalid\n');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('HTTP authorizes before decryption and keeps corrupt content and crypto metadata private', async t => {
  const fixture = await startFixture();
  t.mock.method(console, 'error', () => {});
  try {
    await fixture.db.query('UPDATE documents SET "authTag" = $1 WHERE id IN (1, 3)', ['!']);
    assert.equal((await fixture.request('/api/documents/3')).status, 404);
    assert.equal((await fixture.request('/api/documents/3/permissions')).status, 403);
    const denied = await fixture.request('/api/documents/1');
    assert.equal(denied.status, 500);
    assert.equal(denied.body.detail, 'Internal server error');
    assert.doesNotMatch(JSON.stringify(denied.body), /wrappedKey|authTag|cipher|private notes/);
    const listing = await fixture.request('/api/documents');
    assert.equal(listing.status, 200);
    assert.doesNotMatch(JSON.stringify(listing.body), /content|version|iv|authTag|wrappedKey/);
  } finally { await fixture.close(); }
});
