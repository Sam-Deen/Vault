import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Pool, openDatabase } from '../src/database.js';
import { seedDatabase } from '../src/seed.js';

export async function createTestDatabase(encryption) {
  const adminUrl = process.env.TEST_ADMIN_DATABASE_URL ?? 'postgresql://vault_admin:vault-admin-demo@127.0.0.1:5432/vault';
  const admin = new Pool({ connectionString: adminUrl });
  const name = `vault_test_${randomUUID().replaceAll('-', '')}`;
  await admin.query(`CREATE DATABASE ${name}`);
  const ownerUrl = new URL(adminUrl);
  ownerUrl.pathname = '/' + name;
  const owner = new Pool({ connectionString: ownerUrl.toString() });
  let runtime;
  async function close() {
    await runtime?.end();
    await owner.end();
    await admin.query(`DROP DATABASE ${name}`);
    await admin.end();
  }
  try {
    await owner.query(readFileSync(new URL('../db/02-schema.sql', import.meta.url), 'utf8'));
    await owner.query(readFileSync(new URL('../db/03-access.sql', import.meta.url), 'utf8').replaceAll(':"DBNAME"', name));
    await seedDatabase(owner, encryption);
    const url = new URL(ownerUrl);
    url.username = 'vault_app';
    url.password = 'vault-app-demo';
    runtime = await openDatabase(url.toString(), encryption);
    return { owner, runtime, url: url.toString(), ownerUrl: ownerUrl.toString(), close };
  } catch (error) {
    await close();
    throw error;
  }
}
