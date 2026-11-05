import { HttpError } from '../http-error.js';

export class PermissionService {
  constructor(repository, authorization) {
    this.repository = repository;
    this.authorization = authorization;
  }

  async list(user, documentId) {
    const document = await this.repository.findDocument(documentId);
    await this.authorization.requireManagement(user, document);
    return this.repository.listPermissions(documentId);
  }

  async update(user, documentId, { userId, permission }) {
    const document = await this.repository.findDocument(documentId);
    await this.authorization.requireManagement(user, document);
    const target = await this.repository.findUser(userId);
    if (!target) throw new HttpError(404, 'Target user not found');
    if (!this.authorization.sameOrganization(target, document)) {
      throw new HttpError(400, 'Target user belongs to another organization');
    }
    return this.repository.savePermission(documentId, userId, permission);
  }
}
