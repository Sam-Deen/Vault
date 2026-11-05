import { Pool } from '../src/database.js';
import { seedDatabase } from '../src/seed.js';

const db = new Pool({ connectionString: process.env.ADMIN_DATABASE_URL ?? 'postgresql://vault_admin:vault-admin-demo@127.0.0.1:5432/vault' });
try {
  await seedDatabase(db);
  console.log('Demo users, encrypted documents, and permissions are ready.');
} finally {
  await db.end();
}
