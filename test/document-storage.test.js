import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { DocumentEncryption } from '../src/document-encryption.js';
import { openDatabase } from '../src/database.js';
import { VaultRepository } from '../src/repository.js';
import { startFixture } from '../support/fixture.js';
import { hashPassword } from '../src/passwords.js';

const masterKey = randomBytes(32).toString('hex');
const encryption = new DocumentEncryption(masterKey);

function temporaryDatabase(run) {
  const directory = mkdtempSync(join(tmpdir(), 'vault-encryption-test-'));
  try { run(join(directory, 'vault.sqlite'), directory); }
  finally { rmSync(directory, { recursive: true, force: true }); }
}

function storedRows(db) {
  return {
    documents: db.prepare('SELECT * FROM documents ORDER BY id').all(),
    keys: db.prepare('SELECT * FROM document_keys ORDER BY documentId, version').all(),
  };
}

function legacyDatabase(path) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE organizations (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, passwordHash TEXT NOT NULL,
      organizationId INTEGER NOT NULL REFERENCES organizations(id), role TEXT NOT NULL, totpSecret TEXT, pendingTotpSecret TEXT);
    CREATE TABLE documents (id INTEGER PRIMARY KEY, organizationId INTEGER NOT NULL REFERENCES organizations(id),
      ownerId INTEGER NOT NULL REFERENCES users(id), filename TEXT NOT NULL, content TEXT NOT NULL, createdAt TEXT NOT NULL);
    CREATE TABLE permissions (id INTEGER PRIMARY KEY, documentId INTEGER NOT NULL REFERENCES documents(id),
      userId INTEGER NOT NULL REFERENCES users(id), permission TEXT NOT NULL, UNIQUE(documentId, userId));
    INSERT INTO organizations VALUES (1, 'Original organization');
  `);
  const passwordHash = hashPassword('alice-demo');
  db.prepare('INSERT INTO users VALUES (1, ?, ?, 1, ?, ?, NULL)')
    .run('alice', passwordHash, 'EMPLOYEE', 'JBSWY3DPEHPK3PXP');
  const contents = [`Private migrated text ${randomUUID()}`, 'Second legacy document'];
  for (let i = 0; i < contents.length; i++) {
    db.prepare('INSERT INTO documents VALUES (?, 1, 1, ?, ?, ?)')
      .run(i + 1, `original-${i + 1}.txt`, contents[i], '2026-02-03T04:05:06Z');
  }
  db.exec("INSERT INTO permissions VALUES (42, 1, 1, 'WRITE')");
  db.close();
  return { contents, passwordHash };
}

test('fresh SQLite stores ciphertext and separately wrapped keys, and new versions rotate both IVs and the key', () => {
  const db = openDatabase(':memory:', encryption);
  try {
    const repository = new VaultRepository(db, encryption);
    const first = storedRows(db);
    assert.equal(first.documents.length, 4);
    assert.equal(first.keys.length, 4);
    for (const document of first.documents) {
      assert.equal(document.version, 1);
      assert.notEqual(document.content, repository.readDocumentContent(document.id));
      assert.doesNotMatch(document.content, /CONFIDENTIAL|private notes/);
    }
    const original = repository.readDocumentContent(1);
    assert.equal(repository.saveDocumentVersion(1, original), 2);
    assert.equal(repository.readDocumentContent(1), original);
    const second = storedRows(db);
    assert.equal(second.documents[0].version, 2);
    for (const field of ['content', 'iv', 'authTag']) assert.notEqual(first.documents[0][field], second.documents[0][field]);
    for (const field of ['wrappedKey', 'iv', 'authTag']) assert.notEqual(first.keys[0][field], second.keys[0][field]);
    assert.equal(second.keys.length, 4);
    assert.equal(second.keys[0].version, 2);
    assert.deepEqual(Object.keys(repository.findDocument(1)).sort(), ['createdAt', 'filename', 'id', 'organizationId', 'ownerId']);
  } finally { db.close(); }
});

test('legacy migration preserves content, metadata, grants and TOTP while removing plaintext from the database file', () => {
  temporaryDatabase(path => {
    const original = legacyDatabase(path);
    assert.ok(readFileSync(path).includes(Buffer.from(original.contents[0])));
    let db = openDatabase(path, encryption);
    try {
      const repository = new VaultRepository(db, encryption);
      assert.equal(repository.readDocumentContent(1), original.contents[0]);
      assert.equal(repository.findDocument(1).filename, 'original-1.txt');
      assert.equal(repository.findDocument(1).createdAt, '2026-02-03T04:05:06Z');
      assert.equal(repository.findPermission(1, 1).id, 42);
      assert.equal(repository.findPermission(1, 1).permission, 'WRITE');
      assert.equal(repository.findUser(1).passwordHash, original.passwordHash);
      assert.equal(repository.findUser(1).totpSecret, 'JBSWY3DPEHPK3PXP');
      const stored = storedRows(db);
      db.close();
      db = openDatabase(path, encryption);
      assert.deepEqual(storedRows(db), stored);
    } finally { db.close(); }
    for (const content of original.contents) assert.equal(readFileSync(path).includes(Buffer.from(content)), false);
    assert.equal(existsSync(path + '-wal'), false);
    assert.equal(existsSync(path + '-journal'), false);
  });
});

test('wrong master keys and damaged version markers fail startup without changing encrypted rows', () => {
  temporaryDatabase(path => {
    let db = openDatabase(path, encryption);
    const stored = storedRows(db);
    db.close();
    assert.throws(() => openDatabase(path, new DocumentEncryption(randomBytes(32).toString('hex'))), /authentication failed/);
    db = new DatabaseSync(path);
    assert.deepEqual(storedRows(db), stored);
    db.exec('UPDATE documents SET version = 0 WHERE id = 1');
    const damaged = storedRows(db);
    db.close();
    assert.throws(() => openDatabase(path, encryption), /authentication failed/);
    db = new DatabaseSync(path, { readOnly: true });
    try { assert.deepEqual(storedRows(db), damaged); }
    finally { db.close(); }
  });
});

test('a failed legacy encryption rolls back the whole schema and content migration', () => {
  temporaryDatabase(path => {
    const original = legacyDatabase(path);
    const failing = {
      encrypt(content, context) {
        if (context.id === 2) throw new Error('Simulated encryption failure');
        return encryption.encrypt(content, context);
      },
      decrypt: encryption.decrypt.bind(encryption),
    };
    assert.throws(() => openDatabase(path, failing), /Simulated encryption failure/);
    const db = new DatabaseSync(path, { readOnly: true });
    try {
      assert.equal(db.prepare('PRAGMA table_info(documents)').all().some(column => column.name === 'version'), false);
      assert.deepEqual(db.prepare('SELECT content FROM documents ORDER BY id').all().map(row => row.content), original.contents);
      assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name = 'document_keys'").get(), undefined);
    } finally { db.close(); }
  });
});

test('missing master configuration fails before creating a database', () => {
  temporaryDatabase(path => {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', "import { openDatabase } from './src/database.js'; openDatabase(process.argv[1]);", path], {
      cwd: fileURLToPath(new URL('..', import.meta.url)), env: { ...process.env, DOCUMENT_MASTER_KEY: '' }, encoding: 'utf8',
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /DOCUMENT_MASTER_KEY/);
    assert.equal(existsSync(path), false);
  });
});

test('keygen preserves an existing master key and other environment settings', () => {
  temporaryDatabase((path, directory) => {
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
  });
});

test('HTTP authorizes before decryption and never returns corrupt content or crypto metadata', async t => {
  const fixture = await startFixture();
  t.mock.method(console, 'error', () => {});
  try {
    fixture.db.exec("UPDATE documents SET authTag = '!' WHERE id IN (1, 3)");
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
