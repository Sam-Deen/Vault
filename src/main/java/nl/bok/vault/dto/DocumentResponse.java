package nl.bok.vault.dto;

import nl.bok.vault.entity.Document;
import java.time.Instant;

public record DocumentResponse(Long id, Long organizationId, Long ownerId, String filename,
                               String content, Instant createdAt) {
    public static DocumentResponse from(Document document) {
        return new DocumentResponse(document.getId(), document.getOrganization().getId(),
                document.getOwner().getId(), document.getFilename(), document.getContent(), document.getCreatedAt());
    }
}
