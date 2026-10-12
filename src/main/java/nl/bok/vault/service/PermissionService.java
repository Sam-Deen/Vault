package nl.bok.vault.service;

import nl.bok.vault.dto.PermissionResponse;
import nl.bok.vault.dto.PermissionRequest;
import nl.bok.vault.entity.DocumentPermission;
import nl.bok.vault.repository.UserRepository;
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
    private final UserRepository users;

    public PermissionService(DocumentRepository documents, DocumentPermissionRepository permissions,
                             CurrentUser currentUser, DocumentAuthorization authorization, UserRepository users) {
        this.documents = documents; this.permissions = permissions;
        this.currentUser = currentUser; this.authorization = authorization;
        this.users = users;
    }

    public List<PermissionResponse> list(Long documentId) {
        var document = documents.findById(documentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found"));
        authorization.requireManagement(currentUser.get(), document);
        return permissions.findByDocumentIdOrderByUserId(documentId).stream().map(PermissionResponse::from).toList();
    }

    @Transactional
    public PermissionResponse update(Long documentId, PermissionRequest request) {
        var document = documents.findById(documentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found"));
        // Retain the requester tenant boundary to avoid a separate cross-tenant write flaw.
        if (!authorization.sameOrganization(currentUser.get(), document)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Document belongs to another organization");
        }
        var target = users.findById(request.userId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Target user not found"));
        if (!authorization.sameOrganization(target, document)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Target user belongs to another organization");
        }
        // VULNERABILITY MC2: Missing authorization check for permission management.
        var permission = permissions.findByDocumentIdAndUserId(documentId, target.getId())
                .orElseGet(() -> new DocumentPermission(document, target, request.permission()));
        permission.setPermission(request.permission());
        return PermissionResponse.from(permissions.saveAndFlush(permission));
    }
}
