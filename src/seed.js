import { hashPassword } from './passwords.js';
import { DocumentEncryption } from './document-encryption.js';
import { VaultRepository } from './repository.js';

export async function seedDatabase(db, encryption = new DocumentEncryption()) {
  const repository = new VaultRepository(db, encryption);
  for (const { id } of (await db.query('SELECT id FROM documents')).rows) await repository.readDocumentContent(id);
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query("INSERT INTO organizations VALUES (1, 'Organization A'), (2, 'Organization B') ON CONFLICT DO NOTHING");
    const users = [
      [1, 'alice', 1, 'EMPLOYEE'], [2, 'bob', 1, 'WORKSPACE_MANAGER'],
      [3, 'adminA', 1, 'ORGANIZATION_ADMIN'], [4, 'charlie', 2, 'EMPLOYEE'],
      [5, 'diana', 2, 'WORKSPACE_MANAGER'],
      [6, 'hashAlice', 1, 'EMPLOYEE', 'shared-demo'], [7, 'hashBob', 1, 'EMPLOYEE', 'shared-demo'],
    ];
    for (const [id, username, organizationId, role, password = `${username}-demo`] of users) {
      if (!(await client.query('SELECT id FROM users WHERE id = $1', [id])).rowCount) {
        await client.query('INSERT INTO users (id, username, "passwordHash", "organizationId", role) VALUES ($1, $2, $3, $4, $5)', [id, username, hashPassword(password), organizationId, role]);
      }
    }
    const documents = [
      [1, 1, 1, 'alice-notes.txt', "Alice's private notes from Organization A."],
      [2, 1, 2, 'bob-confidential.txt', "CONFIDENTIAL: Bob's budget document from Organization A."],
      [3, 2, 4, 'charlie-confidential.txt', 'CONFIDENTIAL: Organization B document owned by Charlie. Organization A has no access.'],
      [4, 2, 5, 'diana-project.txt', "Diana's internal project plan from Organization B."],
    ];
    const grant = (document, user) => client.query('INSERT INTO permissions ("documentId", "userId", permission) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [document, user, 'MANAGE']);
    for (const [id, organizationId, ownerId, filename, content] of documents) {
      const encrypted = encryption.encrypt(content, { id, organizationId, version: 1 });
      const inserted = await client.query('INSERT INTO documents VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8) ON CONFLICT DO NOTHING', [id, organizationId, ownerId, filename, encrypted.content, '2026-01-01T12:00:00Z', encrypted.iv, encrypted.authTag]);
      if (inserted.rowCount) {
        await client.query('INSERT INTO document_keys VALUES ($1, 1, $2, $3, $4)', [id, encrypted.wrappedKey, encrypted.keyIv, encrypted.keyAuthTag]);
        await grant(id, ownerId);
      }
    }
    await grant(1, 2);
    await grant(3, 5);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
