package nl.bok.vault.repository;

import nl.bok.vault.entity.Document;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface DocumentRepository extends JpaRepository<Document, Long> {
    List<Document> findByOrganizationIdOrderById(Long organizationId);
}
