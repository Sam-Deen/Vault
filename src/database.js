import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { hashPassword } from './passwords.js';
import { DocumentEncryption } from './document-encryption.js';
import { VaultRepository } from './repository.js';

export function openDatabase(path = 'data/vault.sqlite', encryption = new DocumentEncryption()) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  let transaction = false;
  try {
    // Scrub replaced cells and avoid retaining a legacy plaintext WAL.
    db.exec('PRAGMA journal_mode = DELETE; PRAGMA secure_delete = ON; PRAGMA foreign_keys = ON;');
    db.exec('BEGIN IMMEDIATE');
    transaction = true;
    db.exec(`
    CREATE TABLE IF NOT EXISTS organizations (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, passwordHash TEXT NOT NULL,
      organizationId INTEGER NOT NULL REFERENCES organizations(id), role TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY, organizationId INTEGER NOT NULL REFERENCES organizations(id),
      ownerId INTEGER NOT NULL REFERENCES users(id), filename TEXT NOT NULL,
      content TEXT NOT NULL, createdAt TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 0, iv TEXT, authTag TEXT
    );
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY, documentId INTEGER NOT NULL REFERENCES documents(id),
      userId INTEGER NOT NULL REFERENCES users(id),
      permission TEXT NOT NULL CHECK (permission IN ('READ', 'WRITE', 'MANAGE')),
      UNIQUE(documentId, userId)
    );
    CREATE TABLE IF NOT EXISTS document_keys (
      documentId INTEGER NOT NULL REFERENCES documents(id), version INTEGER NOT NULL,
      wrappedKey TEXT NOT NULL, iv TEXT NOT NULL, authTag TEXT NOT NULL,
      PRIMARY KEY (documentId, version)
    );
  `);
    const columns = db.prepare('PRAGMA table_info(users)').all().map(column => column.name);
    if (!columns.includes('totpSecret')) db.exec('ALTER TABLE users ADD COLUMN totpSecret TEXT');
    if (!columns.includes('pendingTotpSecret')) db.exec('ALTER TABLE users ADD COLUMN pendingTotpSecret TEXT');
    const documentColumns = db.prepare('PRAGMA table_info(documents)').all().map(column => column.name);
    const legacy = !documentColumns.includes('version');
    if (legacy) {
      db.exec('ALTER TABLE documents ADD COLUMN version INTEGER NOT NULL DEFAULT 0; ALTER TABLE documents ADD COLUMN iv TEXT; ALTER TABLE documents ADD COLUMN authTag TEXT;');
    }
    const repository = new VaultRepository(db, encryption);
    const plaintext = legacy ? db.prepare('SELECT id, content FROM documents').all() : [];
    for (const document of plaintext) repository.saveDocumentVersion(document.id, document.content);
    seed(db, repository);
    // Wrong keys, missing keys, and damaged envelopes fail without committing changes.
    for (const { id } of db.prepare('SELECT id FROM documents').all()) repository.readDocumentContent(id);
    db.exec('COMMIT');
    transaction = false;
    if (plaintext.length) db.exec('VACUUM');
    return db;
  } catch (error) {
    if (transaction) db.exec('ROLLBACK');
    db.close();
    throw error;
  }
}

function seed(db, repository) {
  db.exec("INSERT OR IGNORE INTO organizations VALUES (1, 'Organization A'), (2, 'Organization B')");
  const users = [
    [1, 'alice', 1, 'EMPLOYEE'],
    [2, 'bob', 1, 'WORKSPACE_MANAGER'],
    [3, 'adminA', 1, 'ORGANIZATION_ADMIN'],
    [4, 'charlie', 2, 'EMPLOYEE'],
    [5, 'diana', 2, 'WORKSPACE_MANAGER'],
    [6, 'hashAlice', 1, 'EMPLOYEE', 'shared-demo'],
    [7, 'hashBob', 1, 'EMPLOYEE', 'shared-demo'],
  ];
  for (const [id, username, organizationId, role, password = `${username}-demo`] of users) {
    if (!db.prepare('SELECT id FROM users WHERE id = ?').get(id)) {
      db.prepare('INSERT INTO users (id, username, passwordHash, organizationId, role) VALUES (?, ?, ?, ?, ?)')
        .run(id, username, hashPassword(password), organizationId, role);
    }
  }
  const documents = [
    [1, 1, 1, 'alice-notes.txt', "Alice's private notes from Organization A."],
    [2, 1, 2, 'bob-confidential.txt', "CONFIDENTIAL: Bob's budget document from Organization A."],
    [3, 2, 4, 'charlie-confidential.txt', 'CONFIDENTIAL: Organization B document owned by Charlie. Organization A has no access.'],
    [4, 2, 5, 'diana-project.txt', "Diana's internal project plan from Organization B."],
  ];
  const grant = db.prepare("INSERT OR IGNORE INTO permissions (documentId, userId, permission) VALUES (?, ?, 'MANAGE')");
  for (const document of documents) {
    const [id, organizationId, ownerId, filename, content] = document;
    const result = db.prepare("INSERT OR IGNORE INTO documents (id, organizationId, ownerId, filename, content, createdAt) VALUES (?, ?, ?, ?, '', ?)")
      .run(id, organizationId, ownerId, filename, '2026-01-01T12:00:00Z');
    if (result.changes) {
      repository.saveDocumentVersion(id, content);
      grant.run(id, ownerId);
    }
  }
  grant.run(1, 2);
  grant.run(3, 5);
}
