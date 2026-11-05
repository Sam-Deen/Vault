import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { SecurityLogger } from '../src/security-logging.js';
import config from '../monitoring.json' with { type: 'json' };

const path = 'logs/monitoring-demo.jsonl';
const logger = new SecurityLogger(path);
writeFileSync(path, '', { mode: 0o600 });
const below = process.argv.includes('--below');
const requests = {
  'authentication.failed': ['POST', '/api/auth/login', 401, null, null],
  'totp.failed': ['POST', '/api/auth/verify', 401, 1, 1],
  'document.access_denied': ['GET', '/api/documents/:id', 404, 1, 1],
  'permission.modification_denied': ['PUT', '/api/documents/:id/permissions', 403, 1, 1],
  'rate_limited': ['GET', '/api', 429, null, null],
};
let time = Date.now();
for (const [event, threshold] of Object.entries(config.thresholds)) {
  const [method, route, status, userId, organizationId] = requests[event];
  for (let i = 0; i < threshold + (below ? 0 : 1); i++) {
    logger.write({ timestamp: new Date(time++).toISOString(), event, requestId: randomUUID(), method, route, status, userId, organizationId });
  }
}
console.log(`Generated synthetic events ${below ? 'at' : 'above'} each threshold in ${path}.`);
