package nl.bok.vault.repository;

import nl.bok.vault.entity.VaultUser;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<VaultUser, Long> {
    Optional<VaultUser> findByUsername(String username);
}
