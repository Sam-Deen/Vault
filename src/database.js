import pg from 'pg';
import { DocumentEncryption } from './document-encryption.js';
import { VaultRepository } from './repository.js';

export const { Pool } = pg;
pg.types.setTypeParser(20, Number);

export async function openDatabase(connectionString = process.env.DATABASE_URL ?? 'postgresql://vault_app:vault-app-demo@127.0.0.1:5432/vault', encryption = new DocumentEncryption()) {
  const db = new Pool({ connectionString });
  try {
    const repository = new VaultRepository(db, encryption);
    for (const { id } of (await db.query('SELECT id FROM documents')).rows) await repository.readDocumentContent(id);
    return db;
  } catch (error) {
    await db.end();
    throw error;
  }
}
