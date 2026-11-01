import { once } from 'node:events';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/database.js';
import { VaultRepository } from '../src/repository.js';

export async function startFixture() {
  const db = openDatabase(':memory:');
  const repository = new VaultRepository(db);
  const server = createApp(db).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    db, repository,
    async request(path, { user = 'alice', password = `${user}-demo`, method = 'GET', body, headers = {} } = {}) {
      const response = await fetch(base + path, {
        method,
        headers: {
          ...(user ? { Authorization: `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}` } : {}),
          ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
          ...headers,
        },
        body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
      });
      return { status: response.status, body: await response.json(), headers: response.headers };
    },
    async close() {
      await new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
      db.close();
    },
  };
}
