import { createApp } from './app.js';
import { openDatabase } from './database.js';

const host = process.env.SERVER_ADDRESS ?? '127.0.0.1';
const port = Number(process.env.SERVER_PORT ?? 8080);
const db = openDatabase(process.env.DB_PATH);
const server = createApp(db).listen(port, host, () => {
  console.log(`Vault listening on http://${host}:${port}`);
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => db.close()));
}
