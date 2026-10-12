package nl.bok.vault.service;

import nl.bok.vault.dto.PermissionResponse;
import nl.bok.vault.repository.DocumentPermissionRepository;
import nl.bok.vault.repository.DocumentRepository;
import nl.bok.vault.security.CurrentUser;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;

@Service
@Transactional(readOnly = true)
public class PermissionService {
    private final DocumentRepository documents;
    private final DocumentPermissionRepository permissions;
    private final CurrentUser currentUser;
    private final DocumentAuthorization authorization;

    public PermissionService(DocumentRepository documents, DocumentPermissionRepository permissions,
                             CurrentUser currentUser, DocumentAuthorization authorization) {
        this.documents = documents; this.permissions = permissions;
        this.currentUser = currentUser; this.authorization = authorization;
    }

    public List<PermissionResponse> list(Long documentId) {
        var document = documents.findById(documentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found"));
        authorization.requireManagement(currentUser.get(), document);
        return permissions.findByDocumentIdOrderByUserId(documentId).stream().map(PermissionResponse::from).toList();
    }
}
