import { DocumentEncryption } from './document-encryption.js';

export class VaultRepository {
  constructor(db, encryption = new DocumentEncryption()) {
    this.db = db;
    this.encryption = encryption;
  }

  async findUserByUsername(username) {
    return (await this.db.query('SELECT * FROM users WHERE username = $1', [username])).rows[0];
  }

  async findUser(id) {
    return (await this.db.query('SELECT * FROM users WHERE id = $1', [id])).rows[0];
  }

  async savePendingTotpSecret(id, secret) {
    await this.db.query('UPDATE users SET "pendingTotpSecret" = $1 WHERE id = $2', [secret, id]);
  }

  async activateTotpSecret(id) {
    await this.db.query('UPDATE users SET "totpSecret" = "pendingTotpSecret", "pendingTotpSecret" = NULL WHERE id = $1', [id]);
  }

  async findDocument(id) {
    return (await this.db.query('SELECT id, "organizationId", "ownerId", filename, "createdAt" FROM documents WHERE id = $1', [id])).rows[0];
  }

  async searchDocuments(user, filename) {
    return (await this.db.query(`
      SELECT id, "organizationId", "ownerId", filename, "createdAt" FROM documents d
      WHERE "organizationId" = $1 AND ("ownerId" = $2 OR $3 = 'WORKSPACE_MANAGER'
        OR EXISTS (SELECT 1 FROM permissions p WHERE p."documentId" = d.id AND p."userId" = $2))
        AND filename ILIKE $4 ESCAPE '' ORDER BY id
    `, [user.organizationId, user.id, user.role, `%${filename}%`])).rows;
  }

  async readDocumentContent(id) {
    const document = (await this.db.query(`
      SELECT d.*, k."wrappedKey", k.iv AS "keyIv", k."authTag" AS "keyAuthTag"
      FROM documents d JOIN document_keys k ON k."documentId" = d.id AND k.version = d.version
      WHERE d.id = $1
    `, [id])).rows[0];
    return this.encryption.decrypt(document, document && { wrappedKey: document.wrappedKey, iv: document.keyIv, authTag: document.keyAuthTag });
  }

  // Only the current version is retained; administrative setup/tests can replace it.
  async saveDocumentVersion(id, content) {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      const document = (await client.query('SELECT id, "organizationId", version FROM documents WHERE id = $1 FOR UPDATE', [id])).rows[0];
      const version = document.version + 1;
      const encrypted = this.encryption.encrypt(content, { ...document, version });
      await client.query('UPDATE documents SET content = $1, version = $2, iv = $3, "authTag" = $4 WHERE id = $5', [encrypted.content, version, encrypted.iv, encrypted.authTag, id]);
      await client.query('DELETE FROM document_keys WHERE "documentId" = $1', [id]);
      await client.query('INSERT INTO document_keys VALUES ($1, $2, $3, $4, $5)', [id, version, encrypted.wrappedKey, encrypted.keyIv, encrypted.keyAuthTag]);
      await client.query('COMMIT');
      return version;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async findPermission(documentId, userId) {
    return (await this.db.query('SELECT * FROM permissions WHERE "documentId" = $1 AND "userId" = $2', [documentId, userId])).rows[0];
  }

  async listPermissions(documentId) {
    return (await this.db.query('SELECT * FROM permissions WHERE "documentId" = $1 ORDER BY "userId"', [documentId])).rows;
  }

  async savePermission(documentId, userId, permission) {
    return (await this.db.query(`
      INSERT INTO permissions ("documentId", "userId", permission) VALUES ($1, $2, $3)
      ON CONFLICT ("documentId", "userId") DO UPDATE SET permission = excluded.permission
      RETURNING id, "documentId", "userId", permission
    `, [documentId, userId, permission])).rows[0];
  }
}
