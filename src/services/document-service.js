import { HttpError } from '../http-error.js';

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
    if (!this.authorization.canRead(user, document)) throw new HttpError(404, 'Document not found');
    return document;
  }
}

