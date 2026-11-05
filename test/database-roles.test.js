import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Pool } from '../src/database.js';
import { createTestDatabase } from '../support/postgres.js';
import { testEncryption } from '../support/fixture.js';

async function probe(db, sql) {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    return await client.query(sql);
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
}

test('the administration account can create tables and roles and modify data', async () => {
  const database = await createTestDatabase(testEncryption);
  try {
    for (const sql of [
      'CREATE TABLE privilege_probe (id integer)',
      'CREATE TEMP TABLE temporary_probe (id integer)',
      `CREATE ROLE probe_${randomUUID().replaceAll('-', '')}`,
      'ALTER ROLE vault_app SUPERUSER',
      'DELETE FROM organizations WHERE id = -1',
    ]) await probe(database.owner, sql);
  } finally { await database.close(); }
});

test('the application account has only the SQL permissions needed by its routes', async () => {
  const database = await createTestDatabase(testEncryption);
  try {
    const db = database.runtime;
    assert.equal((await db.query('SELECT current_user')).rows[0].current_user, 'vault_app');
    const attributes = (await db.query('SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication FROM pg_roles WHERE rolname = current_user')).rows[0];
    assert.deepEqual(Object.values(attributes), [false, false, false, false]);
    assert.equal((await db.query('SELECT count(*) AS n FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user)')).rows[0].n, 0);
    for (const sql of [
      'SELECT * FROM documents',
      'UPDATE users SET "pendingTotpSecret" = NULL WHERE id = 1',
      "INSERT INTO permissions (\"documentId\", \"userId\", permission) VALUES (2, 1, 'READ') ON CONFLICT (\"documentId\", \"userId\") DO UPDATE SET permission = excluded.permission RETURNING id",
    ]) await probe(db, sql);
    for (const sql of [
      'CREATE TABLE privilege_probe (id integer)', 'CREATE TEMP TABLE temporary_probe (id integer)',
      'CREATE SCHEMA privilege_probe', 'CREATE ROLE vault_role_probe', 'ALTER ROLE vault_app SUPERUSER',
      'SET ROLE vault_admin', 'DROP TABLE documents', 'DELETE FROM organizations WHERE id = -1',
      'DELETE FROM permissions WHERE id = -1', 'UPDATE users SET role = role WHERE id = 1',
      'UPDATE users SET "passwordHash" = "passwordHash" WHERE id = 1',
      'UPDATE documents SET filename = filename WHERE id = 1',
      'UPDATE document_keys SET "wrappedKey" = "wrappedKey" WHERE "documentId" = 1',
      "SELECT setval('permissions_id_seq', 1000)",
      "SELECT nextval('permissions_id_seq')",
    ]) await assert.rejects(probe(db, sql), { code: '42501' }, sql);
  } finally { await database.close(); }
});

test('the read-only account can read business records but cannot mutate them or access auth/key records', async () => {
  const database = await createTestDatabase(testEncryption);
  const url = new URL(database.url);
  url.username = 'vault_readonly';
  url.password = 'vault-readonly-demo';
  const db = new Pool({ connectionString: url.toString() });
  try {
    for (const table of ['organizations', 'documents', 'permissions']) await db.query(`SELECT * FROM ${table}`);
    for (const sql of [
      'SELECT * FROM users', 'SELECT * FROM document_keys',
      'UPDATE documents SET filename = filename WHERE id = 1',
      'DELETE FROM organizations WHERE id = -1',
      "INSERT INTO permissions (\"documentId\", \"userId\", permission) VALUES (2, 1, 'READ')",
      'CREATE TABLE privilege_probe (id integer)', 'CREATE TEMP TABLE temporary_probe (id integer)',
      'CREATE ROLE vault_role_probe', 'SET ROLE vault_admin', 'SET ROLE vault_app',
    ]) await assert.rejects(probe(db, sql), { code: '42501' }, sql);
  } finally { await db.end(); await database.close(); }
});

test('the rebuilt schema contains only business tables and no row-security policies', async () => {
  const database = await createTestDatabase(testEncryption);
  try {
    assert.deepEqual((await database.owner.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")).rows.map(row => row.tablename), ['document_keys', 'documents', 'organizations', 'permissions', 'users']);
    assert.equal((await database.owner.query("SELECT * FROM pg_policies WHERE schemaname = 'public'")).rowCount, 0);
    assert.equal((await database.owner.query("SELECT * FROM pg_class WHERE relnamespace = 'public'::regnamespace AND (relrowsecurity OR relforcerowsecurity)")).rowCount, 0);
  } finally { await database.close(); }
});
