import { HttpError } from '../http-error.js';

export class PermissionService {
  constructor(repository, authorization) {
    this.repository = repository;
    this.authorization = authorization;
  }

  list(user, documentId) {
    const document = this.repository.findDocument(documentId);
    if (!document) throw new HttpError(404, 'Document not found');
    this.authorization.requireManagement(user, document);
    return this.repository.listPermissions(documentId);
  }
}
