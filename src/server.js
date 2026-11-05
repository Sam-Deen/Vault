import { readFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createApp } from './app.js';
import { openDatabase } from './database.js';
import { assignRequestId } from './security-logging.js';

const host = process.env.SERVER_ADDRESS ?? '127.0.0.1';
const port = Number(process.env.SERVER_PORT ?? 8080);
const httpsPort = Number(process.env.HTTPS_PORT ?? 8443);
const tls = {
  key: readFileSync('certs/localhost-key.pem'),
  cert: readFileSync('certs/localhost.pem'),
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
};
const db = await openDatabase();
const server = createHttpsServer(tls, createApp(db)).listen(httpsPort, host, () => {
  console.log(`Vault listening on https://${host}:${httpsPort}`);
});
const redirect = createHttpServer((req, res) => {
  assignRequestId(req, res);
  let target;
  try {
    target = new URL(`https://${req.headers.host}`);
    target.port = String(httpsPort);
  } catch {
    res.writeHead(400).end();
    return;
  }
  res.writeHead(308, { Location: `${target.origin}${req.url}` }).end();
}).listen(port, host, () => {
  console.log(`HTTP on port ${port} redirects to HTTPS`);
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, async () => {
    await Promise.all([server, redirect].map(listener => new Promise(resolve => listener.close(resolve))));
    await db.end();
  });
}
