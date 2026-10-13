package nl.bok.vault.security;

import nl.bok.vault.entity.VaultUser;
import nl.bok.vault.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class CurrentUser {
    private final UserRepository users;
    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entityManager;
    public CurrentUser(UserRepository users) { this.users = users; }

    /** Called inside the application service's transaction. Identity comes only from Spring Security. */
    public VaultUser get() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthenticationCredentialsNotFoundException("Authentication required");
        }
        var user = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new AuthenticationCredentialsNotFoundException("Authentication required"));
        if (!org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Tenant context requires a transaction");
        }
        entityManager.createNativeQuery("select set_config('vault.organization_id', :tenant, true)")
                .setParameter("tenant", user.getOrganization().getId().toString()).getSingleResult();
        return user;
    }
}
