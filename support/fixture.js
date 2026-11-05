import { once } from 'node:events';
import { createApp } from '../src/app.js';
import { createTestDatabase } from './postgres.js';
import { VaultRepository } from '../src/repository.js';
import { createHmac, randomBytes } from 'node:crypto';
import { DocumentEncryption } from '../src/document-encryption.js';

export const testEncryption = new DocumentEncryption(randomBytes(32).toString('hex'));

export function totpCode(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const bytes = [];
  for (const char of secret) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hash = createHmac('sha1', Buffer.from(bytes)).update(counter).digest();
  return String((hash.readUInt32BE(hash[19] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}

export async function startFixture() {
  const database = await createTestDatabase(testEncryption);
  const db = database.owner;
  const repository = new VaultRepository(database.runtime, testEncryption);
  const server = createApp(database.runtime, testEncryption).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  const tokens = new Map();
  async function raw(path, { method = 'GET', body, headers = {} } = {}) {
    const response = await fetch(base + path, {
      method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    return { status: response.status, body: response.status === 204 ? null : await response.json(), headers: response.headers };
  }
  async function login(user, password = `${user}-demo`) {
    const first = await raw('/api/auth/login', { method: 'POST', body: { username: user, password } });
    if (first.status !== 200) return first;
    let secret = (await repository.findUserByUsername(user)).totpSecret;
    if (first.body.enrollmentRequired) {
      const enrollment = await raw('/api/auth/enroll', { method: 'POST', headers: { Authorization: `Bearer ${first.body.token}` } });
      secret = enrollment.body.secret;
    }
    const verified = await raw('/api/auth/verify', { method: 'POST', body: { code: totpCode(secret) }, headers: { Authorization: `Bearer ${first.body.token}` } });
    tokens.set(user, verified.body.token);
    return verified;
  }
  return {
    db, repository, raw, login, base, databaseUrl: database.url,
    async request(path, { user = 'alice', password = `${user}-demo`, method = 'GET', body, headers = {} } = {}) {
      if (user && !tokens.has(user) && password === `${user}-demo`) await login(user, password);
      return raw(path, { method, body, headers: { ...(tokens.has(user) ? { Authorization: `Bearer ${tokens.get(user)}` } : {}), ...headers } });
    },
    async close() {
      await new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
      await database.close();
    },
  };
}
