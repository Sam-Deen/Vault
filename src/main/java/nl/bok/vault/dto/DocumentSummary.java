package nl.bok.vault.dto;

import nl.bok.vault.entity.Document;
import java.time.Instant;

public record DocumentSummary(Long id, Long organizationId, Long ownerId, String filename, Instant createdAt) {
    public static DocumentSummary from(Document document) {
        return new DocumentSummary(document.getId(), document.getOrganization().getId(),
                document.getOwner().getId(), document.getFilename(), document.getCreatedAt());
    }
}
