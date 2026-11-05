import { existsSync, mkdirSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

// Git for Windows includes OpenSSL, even when it is not on PATH.
const gitOpenSSL = `${process.env.ProgramFiles ?? 'C:/Program Files'}/Git/usr/bin/openssl.exe`;
const openssl = process.platform === 'win32' && existsSync(gitOpenSSL) ? gitOpenSSL : 'openssl';
mkdirSync('certs', { recursive: true });
if (!existsSync('certs/localhost.pem') || !existsSync('certs/localhost-key.pem')) execFileSync(openssl, [
  'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '365',
  '-keyout', 'certs/localhost-key.pem', '-out', 'certs/localhost.pem',
  '-subj', '/CN=localhost',
  '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1',
], { stdio: 'inherit' });
chmodSync('certs/localhost-key.pem', 0o600);
console.log('Development certificate is ready in certs/.');
