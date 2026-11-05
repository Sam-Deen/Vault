import pg from 'pg';

const url = new URL(process.env.DATABASE_URL ?? 'postgresql://vault_app:vault-app-demo@127.0.0.1:5432/vault');
url.username = 'vault_readonly';
url.password = 'vault-readonly-demo';
const client = new pg.Client({ connectionString: url.toString() });
await client.connect();
try {
  console.log('Account:', (await client.query('SELECT current_user')).rows[0].current_user);
  console.log('RLS:', (await client.query("SELECT relrowsecurity FROM pg_class WHERE oid = 'documents'::regclass")).rows[0].relrowsecurity);
  for (const organization of [null, 1, 2]) {
    await client.query('BEGIN');
    try {
      if (organization !== null) await client.query("SELECT set_config('vault.organization_id', $1, true)", [String(organization)]);
      console.log(`\nOrganization context: ${organization ?? 'none'}`);
      console.log('SELECT id, "organizationId", filename FROM documents ORDER BY id;');
      console.table((await client.query('SELECT id, "organizationId", filename FROM documents ORDER BY id')).rows);
      if (organization === 1) {
        console.log('Attempt organization B: SELECT id FROM documents WHERE "organizationId" = 2;');
        console.log((await client.query('SELECT id FROM documents WHERE "organizationId" = 2')).rows);
      }
    } finally { await client.query('ROLLBACK'); }
  }
} finally { await client.end(); }
