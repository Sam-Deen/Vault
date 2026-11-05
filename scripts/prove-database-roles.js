import { Pool } from '../src/database.js';

const adminUrl = process.env.ADMIN_DATABASE_URL ?? 'postgresql://vault_admin:vault-admin-demo@127.0.0.1:5432/vault';
const operations = [
  ['Read documents', 'SELECT id, filename FROM documents LIMIT 1'],
  ['Update TOTP', 'UPDATE users SET "pendingTotpSecret" = "pendingTotpSecret" WHERE id = 1'],
  ['Create table', 'CREATE TABLE privilege_probe (id integer)'],
  ['Create temporary table', 'CREATE TEMP TABLE temporary_probe (id integer)'],
  ['Create role', 'CREATE ROLE vault_role_probe'],
  ['Change role privileges', 'ALTER ROLE vault_app SUPERUSER'],
  ['Delete unrelated records', 'DELETE FROM organizations WHERE id = -1'],
];
for (const [role, password] of [['vault_admin', 'vault-admin-demo'], ['vault_app', 'vault-app-demo'], ['vault_readonly', 'vault-readonly-demo']]) {
  const url = new URL(adminUrl);
  url.username = role;
  url.password = password;
  const db = new Pool({ connectionString: url.toString() });
  const client = await db.connect();
  const results = [];
  try {
    for (const [operation, sql] of operations) {
      await client.query('BEGIN');
      try {
        await client.query(sql);
        results.push({ operation, result: 'ALLOWED' });
      } catch (error) {
        results.push({ operation, result: `DENIED (${error.code})` });
      } finally {
        await client.query('ROLLBACK');
      }
    }
    console.log(role);
    console.table(results);
  } finally {
    client.release();
    await db.end();
  }
}
