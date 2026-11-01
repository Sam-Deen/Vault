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
}
