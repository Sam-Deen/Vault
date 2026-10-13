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
    private final SecurityAudit audit;

    public PermissionService(DocumentRepository documents, DocumentPermissionRepository permissions,
                             CurrentUser currentUser, DocumentAuthorization authorization, UserRepository users, SecurityAudit audit) {
        this.documents = documents; this.permissions = permissions;
        this.currentUser = currentUser; this.authorization = authorization;
        this.users = users; this.audit = audit;
    }

    public List<PermissionResponse> list(Long documentId) {
        var user = currentUser.get();
        var document = documents.findById(documentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.FORBIDDEN, "Document management permission required"));
        authorization.requireManagement(user, document);
        return permissions.findByDocumentIdOrderByUserId(documentId).stream().map(PermissionResponse::from).toList();
    }

    @Transactional
    public PermissionResponse update(Long documentId, PermissionRequest request) {
        var user = currentUser.get();
        var document = documents.findById(documentId).orElse(null);
        try {
            if (document == null) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Document management permission required");
            }
            authorization.requireManagement(user, document);
        } catch (ResponseStatusException denied) {
            audit.record(user, "PERMISSION_UPDATE", documentId, "denied", "management_not_authorized");
            throw denied;
        }
        var target = users.findById(request.userId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Target user not found"));
        if (!authorization.sameOrganization(target, document)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Target user belongs to another organization");
        }
        var permission = permissions.findByDocumentIdAndUserId(documentId, target.getId())
                .orElseGet(() -> new DocumentPermission(document, target, request.permission()));
        permission.setPermission(request.permission());
        var response = PermissionResponse.from(permissions.saveAndFlush(permission));
        // Emit success only after the transaction actually commits.
        org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                new org.springframework.transaction.support.TransactionSynchronization() {
                    @Override public void afterCommit() {
                        audit.record(user, "PERMISSION_UPDATE", documentId, "allowed", "authorized");
                    }
                });
        return response;
    }
}
