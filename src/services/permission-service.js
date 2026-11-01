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

  update(user, documentId, { userId, permission }) {
    const document = this.repository.findDocument(documentId);
    if (!document) throw new HttpError(404, 'Document not found');
    if (!this.authorization.sameOrganization(user, document)) {
      throw new HttpError(403, 'Document belongs to another organization');
    }
    const target = this.repository.findUser(userId);
    if (!target) throw new HttpError(404, 'Target user not found');
    if (!this.authorization.sameOrganization(target, document)) {
      throw new HttpError(400, 'Target user belongs to another organization');
    }
    // MC2: deliberately missing document management authorization.
    return this.repository.savePermission(documentId, userId, permission);
  }
}
