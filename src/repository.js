export class VaultRepository {
  constructor(db) {
    this.db = db;
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
    return this.db.prepare('SELECT * FROM documents WHERE id = ?').get(id);
  }

  listDocuments(organizationId) {
    return this.db.prepare('SELECT * FROM documents WHERE organizationId = ? ORDER BY id').all(organizationId);
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
