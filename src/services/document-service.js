import { HttpError } from '../http-error.js';

export class DocumentService {
  constructor(repository, authorization) {
    this.repository = repository;
    this.authorization = authorization;
  }

  list(user) {
    return this.search(user, '');
  }

  search(user, filename) {
    return this.repository.searchDocuments(user, filename);
  }

  async get(user, id) {
    const document = await this.repository.findDocument(id);
    if (!await this.authorization.canRead(user, document)) throw new HttpError(404, 'Document not found');
    return { ...document, content: await this.repository.readDocumentContent(id) };
  }
}

