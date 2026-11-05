import { readFileSync } from 'node:fs';
import { SecurityMonitor } from '../src/security-monitor.js';
import config from '../monitoring.json' with { type: 'json' };

const path = process.argv[2] ?? process.env.SECURITY_LOG_FILE ?? 'logs/security.jsonl';
const monitor = new SecurityMonitor(config);
const events = readFileSync(path, 'utf8').split('\n').filter(line => line.trim()).map(line => JSON.parse(line));
events.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
for (const event of events) {
  const alert = monitor.inspect(event);
  if (alert) console.log(JSON.stringify(alert));
}
