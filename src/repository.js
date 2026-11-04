import { DocumentEncryption } from './document-encryption.js';

export class VaultRepository {
  constructor(db, encryption = new DocumentEncryption()) {
    this.db = db;
    this.encryption = encryption;
  }

  findUserByUsername(username) {
    return this.db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  }

  findUser(id) {
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  }

  savePendingTotpSecret(id, secret) {
    this.db.prepare('UPDATE users SET pendingTotpSecret = ? WHERE id = ?').run(secret, id);
  }

  activateTotpSecret(id) {
    this.db.prepare('UPDATE users SET totpSecret = pendingTotpSecret, pendingTotpSecret = NULL WHERE id = ?').run(id);
  }

  findDocument(id) {
    return this.db.prepare('SELECT id, organizationId, ownerId, filename, createdAt FROM documents WHERE id = ?').get(id);
  }

  listDocuments(organizationId) {
    return this.db.prepare('SELECT id, organizationId, ownerId, filename, createdAt FROM documents WHERE organizationId = ? ORDER BY id').all(organizationId);
  }

  searchDocuments(user, filename) {
    return this.db.prepare(`
      SELECT id, organizationId, ownerId, filename, createdAt FROM documents d
      WHERE organizationId = ? AND (ownerId = ? OR ? = 'WORKSPACE_MANAGER'
        OR EXISTS (SELECT 1 FROM permissions p WHERE p.documentId = d.id AND p.userId = ?))
        AND filename LIKE '%${filename}%' ORDER BY id
    `).all(user.organizationId, user.id, user.role, user.id);
  }

  readDocumentContent(id) {
    const document = this.db.prepare('SELECT * FROM documents WHERE id = ?').get(id);
    const key = this.db.prepare('SELECT * FROM document_keys WHERE documentId = ? AND version = ?').get(id, document.version);
    return this.encryption.decrypt(document, key);
  }

  // This MVP retains only the current version; replacing content rotates its key.
  saveDocumentVersion(id, content) {
    this.db.exec('SAVEPOINT document_version');
    try {
      const document = this.db.prepare('SELECT id, organizationId, version FROM documents WHERE id = ?').get(id);
      if (!document) throw new Error('Document not found');
      const version = document.version + 1;
      const encrypted = this.encryption.encrypt(content, { ...document, version });
      this.db.prepare('UPDATE documents SET content = ?, version = ?, iv = ?, authTag = ? WHERE id = ?')
        .run(encrypted.content, version, encrypted.iv, encrypted.authTag, id);
      this.db.prepare('INSERT INTO document_keys (documentId, version, wrappedKey, iv, authTag) VALUES (?, ?, ?, ?, ?)')
        .run(id, version, encrypted.wrappedKey, encrypted.keyIv, encrypted.keyAuthTag);
      this.db.prepare('DELETE FROM document_keys WHERE documentId = ? AND version <> ?').run(id, version);
      this.db.exec('RELEASE document_version');
      return version;
    } catch (error) {
      this.db.exec('ROLLBACK TO document_version; RELEASE document_version');
      throw error;
    }
  }

  findPermission(documentId, userId) {
    return this.db.prepare('SELECT * FROM permissions WHERE documentId = ? AND userId = ?').get(documentId, userId);
  }

  listPermissions(documentId) {
    return this.db.prepare('SELECT * FROM permissions WHERE documentId = ? ORDER BY userId').all(documentId);
  }

  savePermission(documentId, userId, permission) {
    return this.db.prepare(`
      INSERT INTO permissions (documentId, userId, permission) VALUES (?, ?, ?)
      ON CONFLICT (documentId, userId) DO UPDATE SET permission = excluded.permission
      RETURNING id, documentId, userId, permission
    `).get(documentId, userId, permission);
  }
}
