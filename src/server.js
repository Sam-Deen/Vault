import { createApp } from './app.js';

const host = process.env.SERVER_ADDRESS ?? '127.0.0.1';
const port = Number(process.env.SERVER_PORT ?? 8080);
createApp().listen(port, host, () => {
  console.log(`Vault listening on http://${host}:${port}`);
});
