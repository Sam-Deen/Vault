import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { SecurityMonitor } from '../src/security-monitor.js';
import config from '../monitoring.json' with { type: 'json' };

const event = (name, time, extra = {}) => ({ event: name, timestamp: new Date(time).toISOString(), requestId: `request-${time}`, userId: 1, organizationId: 1, ...extra });

test('each rule alerts only when its configured threshold is exceeded and correlates triggering requests', () => {
  for (const [name, threshold] of Object.entries(config.thresholds)) {
    const monitor = new SecurityMonitor(config);
    for (let i = 0; i < threshold; i++) assert.equal(monitor.inspect(event(name, i)), undefined);
    const alert = monitor.inspect(event(name, threshold));
    assert.equal(alert.event, 'security.alert');
    assert.equal(alert.sourceEvent, name);
    assert.equal(alert.count, threshold + 1);
    assert.equal(alert.threshold, threshold);
    assert.equal(alert.windowSeconds, config.windowSeconds);
    assert.equal(alert.requestId, `request-${threshold}`);
    assert.equal(alert.timestamp, new Date(threshold).toISOString());
    assert.deepEqual(alert.requestIds, Array.from({ length: threshold + 1 }, (_, i) => `request-${i}`));
    assert.equal(monitor.inspect(event(name, threshold + 1)), undefined);
  }
});

test('expired events do not count and a later burst can alert again', () => {
  const monitor = new SecurityMonitor({ windowSeconds: 10, thresholds: { 'totp.failed': 2 } });
  for (const time of [0, 9000, 10000]) assert.equal(monitor.inspect(event('totp.failed', time)), undefined);
  assert.equal(monitor.inspect(event('totp.failed', 10001)).count, 3);
  for (const time of [20001, 20002]) assert.equal(monitor.inspect(event('totp.failed', time)), undefined);
  assert.equal(monitor.inspect(event('totp.failed', 20003)).count, 3);
});

test('different users, organizations and event types never share a threshold', () => {
  const monitor = new SecurityMonitor({ windowSeconds: 60, thresholds: { 'totp.failed': 1, 'document.access_denied': 1 } });
  assert.equal(monitor.inspect(event('totp.failed', 0)), undefined);
  assert.equal(monitor.inspect(event('totp.failed', 1, { userId: 2 })), undefined);
  assert.equal(monitor.inspect(event('totp.failed', 2, { organizationId: 2 })), undefined);
  assert.equal(monitor.inspect(event('document.access_denied', 3)), undefined);
  const alert = monitor.inspect(event('totp.failed', 4));
  assert.equal(alert.userId, 1);
  assert.equal(alert.organizationId, 1);
  assert.deepEqual(alert.requestIds, ['request-0', 'request-4']);
});

test('anonymous authentication failures are counted together and successes do not generate alerts', () => {
  const monitor = new SecurityMonitor({ windowSeconds: 60, thresholds: { 'authentication.failed': 1 } });
  assert.equal(monitor.inspect(event('authentication.failed', 0, { userId: null, organizationId: null })), undefined);
  assert.equal(monitor.inspect(event('authentication.succeeded', 1)), undefined);
  assert.equal(monitor.inspect(event('permission.modified', 2)), undefined);
  const alert = monitor.inspect(event('authentication.failed', 3, { userId: null, organizationId: null }));
  assert.equal(alert.userId, null);
  assert.equal(alert.organizationId, null);
  assert.equal(alert.count, 2);
});

test('alerts omit arbitrary input fields and sensitive values', () => {
  const monitor = new SecurityMonitor({ windowSeconds: 60, thresholds: { 'totp.failed': 0 } });
  const alert = monitor.inspect(event('totp.failed', 0, { password: 'secret-marker', token: 'secret-marker', totpSecret: 'secret-marker', content: 'secret-marker' }));
  assert.ok(!JSON.stringify(alert).includes('secret-marker'));
  assert.deepEqual(Object.keys(alert).sort(), ['count', 'event', 'organizationId', 'requestId', 'requestIds', 'sourceEvent', 'threshold', 'timestamp', 'userId', 'windowSeconds'].sort());
});

test('demo and monitoring commands produce zero alerts at thresholds and five alerts above them', () => {
  const directory = mkdtempSync(join(tmpdir(), 'vault-monitor-'));
  const generator = fileURLToPath(new URL('../scripts/generate-monitoring-events.js', import.meta.url));
  const script = fileURLToPath(new URL('../scripts/monitor-security.js', import.meta.url));
  const run = (path, args = [], env = {}) => {
    const result = spawnSync(process.execPath, [path, ...args], { cwd: directory, env: { ...process.env, ...env }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  try {
    const path = join(directory, 'logs/monitoring-demo.jsonl');
    run(generator, ['--below']);
    assert.equal(run(script, [path]), '');
    run(generator);
    const stored = readFileSync(path, 'utf8');
    writeFileSync(path, stored.trim().split('\n').reverse().join('\n') + '\n\n');
    const alerts = run(script, [path]).trim().split('\n').map(JSON.parse);
    assert.deepEqual(alerts.map(alert => alert.sourceEvent), Object.keys(config.thresholds));
    for (const alert of alerts) assert.equal(alert.count, alert.threshold + 1);
    assert.equal(run(script, [], { SECURITY_LOG_FILE: path }), run(script, [path]));
    assert.equal(readFileSync(path, 'utf8'), stored.trim().split('\n').reverse().join('\n') + '\n\n');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
