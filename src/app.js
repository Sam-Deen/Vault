import express from 'express';
import { STATUS_CODES } from 'node:http';
import { VaultRepository } from './repository.js';
import { authenticate } from './authentication.js';
import { HttpError } from './http-error.js';
import { DocumentAuthorization } from './services/document-authorization.js';
import { DocumentService } from './services/document-service.js';

export function createApp(db) {
  const app = express();
  const repository = new VaultRepository(db);
  const authorization = new DocumentAuthorization(repository);
  const documents = new DocumentService(repository, authorization);
  app.disable('x-powered-by');
  app.get('/api/health', (req, res) => res.json({ status: 'UP' }));
  app.use(authenticate(repository));
  app.param('id', (req, res, next, value) => {
    if (!/^-?\d+$/.test(value) || !Number.isSafeInteger(Number(value))) {
      return next(new HttpError(400, 'Document ID must be an integer'));
    }
    req.documentId = Number(value);
    next();
  });
  app.get('/api/documents', (req, res) => res.json(documents.list(req.user)));
  app.get('/api/documents/:id', (req, res) => res.json(documents.get(req.user, req.documentId)));
  app.use((req, res, next) => next(new HttpError(404, 'Not found')));
  app.use((error, req, res, next) => {
    const status = error instanceof HttpError ? error.status : 500;
    if (status === 500) console.error(error);
    res.status(status).type('application/problem+json').json({
      type: 'about:blank', title: STATUS_CODES[status], status,
      detail: status === 500 ? 'Internal server error' : error.message,
      instance: req.path,
    });
  });
  return app;
}
