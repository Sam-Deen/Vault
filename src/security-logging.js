import { randomUUID } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export class SecurityLogger {
  constructor(path = process.env.SECURITY_LOG_FILE ?? 'logs/security.jsonl') {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
  }

  write({ timestamp, event, requestId, method, route, status, userId, organizationId, documentId, targetUserId, permission }) {
    appendFileSync(this.path, JSON.stringify({ timestamp, event, requestId, method, route, status, userId, organizationId, documentId, targetUserId, permission }) + '\n', { mode: 0o600 });
  }
}

export function assignRequestId(req, res) {
  req.requestId = randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
}

function eventFor(req, status) {
  if (status === 429) return 'rate_limited';
  if (req.method === 'POST' && req.route?.path === '/api/auth/login') {
    return status === 200 ? 'authentication.password_accepted' : 'authentication.failed';
  }
  if (req.method === 'POST' && req.route?.path === '/api/auth/verify') {
    return status === 200 ? 'authentication.succeeded' : req.auth && status === 401 ? 'totp.failed' : 'authentication.failed';
  }
  if (req.method === 'PUT' && req.route?.path === '/api/documents/:id/permissions') {
    return status === 200 ? 'permission.modified' : 'permission.modification_denied';
  }
  if ((req.path === '/api/documents' || req.path.startsWith('/api/documents/')) && [401, 403, 404].includes(status)) {
    return 'document.access_denied';
  }
}

export function securityLogging(logger) {
  return (req, res, next) => {
    assignRequestId(req, res);
    res.once('finish', () => {
      const event = eventFor(req, res.statusCode);
      if (!event) return;
      const user = req.user ?? req.auth?.user ?? req.securityUser;
      logger.write({
        timestamp: new Date().toISOString(), event, requestId: req.requestId,
        method: req.method, route: req.route?.path ?? '/api', status: res.statusCode,
        userId: user?.id ?? null, organizationId: user?.organizationId ?? null,
        documentId: req.documentId,
        targetUserId: event.startsWith('permission.') && Number.isSafeInteger(req.body?.userId) ? req.body.userId : undefined,
        permission: event.startsWith('permission.') && ['READ', 'WRITE', 'MANAGE'].includes(req.body?.permission) ? req.body.permission : undefined,
      });
    });
    next();
  };
}
