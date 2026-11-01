export class DocumentService {
  constructor(repository, authorization) {
    this.repository = repository;
    this.authorization = authorization;
  }

  list(user) {
    return this.repository.listDocuments(user.organizationId)
      .filter(document => this.authorization.canRead(user, document))
      .map(({ content, ...summary }) => summary);
  }

  get(user, id) {
    const document = this.repository.findDocument(id);
    if (!document) throw new HttpError(404, 'Document not found');
    // MC1: deliberately missing organization and document authorization.
    return document;
  }
}
import { HttpError } from '../http-error.js';

