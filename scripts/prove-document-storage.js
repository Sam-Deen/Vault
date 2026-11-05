import { openDatabase } from '../src/database.js';

const db = await openDatabase();
try {
  console.log('Encrypted document rows in PostgreSQL:');
  console.log(JSON.stringify((await db.query('SELECT id, version, content, iv, "authTag" FROM documents ORDER BY id')).rows, null, 2));
  console.log('Separately wrapped document key:');
  console.log(JSON.stringify((await db.query('SELECT * FROM document_keys WHERE "documentId" = 1')).rows[0], null, 2));
} finally {
  await db.end();
}
