import express from 'express';
import { STATUS_CODES } from 'node:http';
import { VaultRepository } from './repository.js';
import { createAuthentication } from './authentication.js';
import { generateTotpSecret, verifyTotp } from './totp.js';
import QRCode from 'qrcode';
import { HttpError } from './http-error.js';
import { DocumentAuthorization } from './services/document-authorization.js';
import { DocumentService } from './services/document-service.js';
import { PermissionService } from './services/permission-service.js';

export function createApp(db) {
  const app = express();
  const repository = new VaultRepository(db);
  const authorization = new DocumentAuthorization(repository);
  const documents = new DocumentService(repository, authorization);
  const permissions = new PermissionService(repository, authorization);
  const authentication = createAuthentication(repository);
  app.disable('x-powered-by');
  app.use(express.static('public'));
  app.get('/api/health', (req, res) => res.json({ status: 'UP' }));
  const json = express.json({ limit: '4kb' });
  app.post('/api/auth/login', json, (req, res) => {
    const { username, password } = req.body ?? {};
    res.set('Cache-Control', 'no-store').json(authentication.login(username, password));
  });
  app.post('/api/auth/enroll', authentication.pending, async (req, res) => {
    const user = req.auth.user;
    if (user.totpSecret) throw new HttpError(409, 'TOTP already enrolled');
    const secret = user.pendingTotpSecret ?? generateTotpSecret();
    if (!user.pendingTotpSecret) repository.savePendingTotpSecret(user.id, secret);
    const uri = `otpauth://totp/Vault:${encodeURIComponent(user.username)}?secret=${secret}&issuer=Vault&algorithm=SHA1&digits=6&period=30`;
    res.set('Cache-Control', 'no-store').json({ secret, qrCode: await QRCode.toDataURL(uri) });
  });
  app.post('/api/auth/verify', authentication.pending, json, (req, res) => {
    const user = req.auth.user;
    const secret = user.totpSecret ?? user.pendingTotpSecret;
    if (!secret || !verifyTotp(secret, req.body?.code)) throw new HttpError(401, 'Invalid TOTP code');
    if (!user.totpSecret) repository.activateTotpSecret(user.id);
    res.set('Cache-Control', 'no-store').json(authentication.complete(req));
  });
  app.post('/api/auth/logout', (req, res) => {
    authentication.logout(req);
    res.status(204).end();
  });
  app.use(authentication.protected);
  app.param('id', (req, res, next, value) => {
    if (!/^-?\d+$/.test(value) || !Number.isSafeInteger(Number(value))) {
      return next(new HttpError(400, 'Document ID must be an integer'));
    }
    req.documentId = Number(value);
    next();
  });
  app.get('/api/documents', (req, res) => res.json(documents.list(req.user)));
  app.get('/api/documents/:id', (req, res) => res.json(documents.get(req.user, req.documentId)));
  app.get('/api/documents/:id/permissions', (req, res) => {
    res.json(permissions.list(req.user, req.documentId));
  });
  app.put('/api/documents/:id/permissions', (req, res, next) => {
    if (!req.is('application/json')) return next(new HttpError(415, 'Content-Type must be application/json'));
    next();
  }, express.json(), (req, res) => {
    const { userId, permission } = req.body ?? {};
    if (!Number.isSafeInteger(userId) || userId <= 0 || !['READ', 'WRITE', 'MANAGE'].includes(permission)) {
      throw new HttpError(400, 'A positive userId and READ, WRITE or MANAGE permission are required');
    }
    res.json(permissions.update(req.user, req.documentId, { userId, permission }));
  });
  app.use((req, res, next) => next(new HttpError(404, 'Not found')));
  app.use((error, req, res, next) => {
    const status = error instanceof HttpError ? error.status
      : error.type === 'entity.parse.failed' ? 400
      : error.type === 'entity.too.large' ? 413
      : error.status === 415 ? 415 : 500;
    if (status === 500) console.error(error);
    res.status(status).type('application/problem+json').json({
      type: 'about:blank', title: STATUS_CODES[status], status,
      detail: status === 500 ? 'Internal server error'
        : error.type === 'entity.parse.failed' ? 'Malformed JSON' : error.message,
      instance: req.path,
    });
  });
  return app;
}
