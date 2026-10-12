package nl.bok.vault.repository;

import nl.bok.vault.entity.DocumentPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface DocumentPermissionRepository extends JpaRepository<DocumentPermission, Long> {
    Optional<DocumentPermission> findByDocumentIdAndUserId(Long documentId, Long userId);
    List<DocumentPermission> findByDocumentIdOrderByUserId(Long documentId);
}
