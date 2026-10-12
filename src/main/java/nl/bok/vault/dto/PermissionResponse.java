package nl.bok.vault.dto;

import nl.bok.vault.entity.DocumentPermission;
import nl.bok.vault.entity.Permission;

public record PermissionResponse(Long id, Long documentId, Long userId, Permission permission) {
    public static PermissionResponse from(DocumentPermission permission) {
        return new PermissionResponse(permission.getId(), permission.getDocument().getId(),
                permission.getUser().getId(), permission.getPermission());
    }
}
