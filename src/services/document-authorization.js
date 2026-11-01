import { HttpError } from '../http-error.js';

export class DocumentAuthorization {
  constructor(repository) {
    this.repository = repository;
  }

  sameOrganization(user, document) {
    return Boolean(document && user.organizationId === document.organizationId);
  }

  canRead(user, document) {
    return this.sameOrganization(user, document) && (
      user.id === document.ownerId || user.role === 'WORKSPACE_MANAGER' ||
      Boolean(this.repository.findPermission(document.id, user.id))
    );
  }

  requireManagement(user, document) {
    const allowed = this.sameOrganization(user, document) && (
      user.id === document.ownerId || user.role === 'WORKSPACE_MANAGER' ||
      this.repository.findPermission(document.id, user.id)?.permission === 'MANAGE'
    );
    if (!allowed) throw new HttpError(403, 'Document management permission required');
  }
}
