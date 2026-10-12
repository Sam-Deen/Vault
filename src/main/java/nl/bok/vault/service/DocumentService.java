package nl.bok.vault.service;

import nl.bok.vault.dto.DocumentSummary;
import nl.bok.vault.dto.DocumentResponse;
import nl.bok.vault.repository.DocumentRepository;
import nl.bok.vault.security.CurrentUser;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
@Transactional(readOnly = true)
public class DocumentService {
    private final DocumentRepository documents;
    private final CurrentUser currentUser;
    private final DocumentAuthorization authorization;

    public DocumentService(DocumentRepository documents, CurrentUser currentUser, DocumentAuthorization authorization) {
        this.documents = documents; this.currentUser = currentUser; this.authorization = authorization;
    }

    public List<DocumentSummary> listAccessible() {
        var user = currentUser.get();
        return documents.findByOrganizationIdOrderById(user.getOrganization().getId()).stream()
                .filter(document -> authorization.canRead(user, document))
                .map(DocumentSummary::from).toList();
    }

    public DocumentResponse getById(Long documentId) {
        // VULNERABILITY MC1: Missing tenant and document authorization checks.
        var document = documents.findById(documentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found"));
        return DocumentResponse.from(document);
    }
}
