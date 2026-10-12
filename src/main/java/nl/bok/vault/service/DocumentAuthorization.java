package nl.bok.vault.service;

import nl.bok.vault.entity.*;
import nl.bok.vault.repository.DocumentPermissionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class DocumentAuthorization {
    private final DocumentPermissionRepository permissions;
    public DocumentAuthorization(DocumentPermissionRepository permissions) { this.permissions = permissions; }

    public boolean canRead(VaultUser user, Document document) {
        if (!sameOrganization(user, document)) { return false; }
        // Workspace managers manage the single workspace in their own organization.
        return user.getRole() == Role.WORKSPACE_MANAGER
                || document.getOwner().getId().equals(user.getId())
                || permissions.findByDocumentIdAndUserId(document.getId(), user.getId()).isPresent();
    }

    public boolean sameOrganization(VaultUser user, Document document) {
        return user.getOrganization().getId().equals(document.getOrganization().getId());
    }
}
