import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openDatabase } from '../src/database.js';

// A fresh on-disk database makes branch comparisons independent of earlier runs.
const directory = mkdtempSync(join(tmpdir(), 'vault-storage-proof-'));
const path = join(directory, 'vault.sqlite');
let db;
try {
  openDatabase(path).close();
  db = new DatabaseSync(path, { readOnly: true });
  const columns = db.prepare('PRAGMA table_info(documents)').all().map(column => column.name);
  const encrypted = columns.includes('authTag');
  const fields = encrypted ? 'id, version, content, iv, authTag' : 'id, content';
  console.log(`Stored document rows (${encrypted ? 'encrypted' : 'plaintext'}):`);
  console.log(JSON.stringify(db.prepare(`SELECT ${fields} FROM documents ORDER BY id`).all(), null, 2));
  if (encrypted) {
    console.log('Separately stored, encrypted document key (document 1):');
    console.log(JSON.stringify(db.prepare('SELECT * FROM document_keys WHERE documentId = 1').get(), null, 2));
  }
} finally {
  db?.close();
  rmSync(directory, { recursive: true, force: true });
}
