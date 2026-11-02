import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { hashPassword } from './passwords.js';

export function openDatabase(path = 'data/vault.sqlite') {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA foreign_keys = ON;
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
      content TEXT NOT NULL, createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY, documentId INTEGER NOT NULL REFERENCES documents(id),
      userId INTEGER NOT NULL REFERENCES users(id),
      permission TEXT NOT NULL CHECK (permission IN ('READ', 'WRITE', 'MANAGE')),
      UNIQUE(documentId, userId)
    );
  `);
  const columns = db.prepare('PRAGMA table_info(users)').all().map(column => column.name);
  if (!columns.includes('totpSecret')) db.exec('ALTER TABLE users ADD COLUMN totpSecret TEXT');
  if (!columns.includes('pendingTotpSecret')) db.exec('ALTER TABLE users ADD COLUMN pendingTotpSecret TEXT');
  seed(db);
  return db;
}

function seed(db) {
  db.exec('BEGIN');
  try {
    db.exec("INSERT OR IGNORE INTO organizations VALUES (1, 'Organization A'), (2, 'Organization B')");
    const users = [
      [1, 'alice', 1, 'EMPLOYEE'],
      [2, 'bob', 1, 'WORKSPACE_MANAGER'],
      [3, 'adminA', 1, 'ORGANIZATION_ADMIN'],
      [4, 'charlie', 2, 'EMPLOYEE'],
      [5, 'diana', 2, 'WORKSPACE_MANAGER'],
    ];
    for (const [id, username, organizationId, role] of users) {
      if (!db.prepare('SELECT id FROM users WHERE id = ?').get(id)) {
        db.prepare('INSERT INTO users (id, username, passwordHash, organizationId, role) VALUES (?, ?, ?, ?, ?)')
          .run(id, username, hashPassword(`${username}-demo`), organizationId, role);
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
      const result = db.prepare('INSERT OR IGNORE INTO documents VALUES (?, ?, ?, ?, ?, ?)')
        .run(...document, '2026-01-01T12:00:00Z');
      if (result.changes) grant.run(document[0], document[2]);
    }
    grant.run(1, 2);
    grant.run(3, 5);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    db.close();
    throw error;
  }
}
