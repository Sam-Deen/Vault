package nl.bok.vault.config;

import nl.bok.vault.entity.*;
import nl.bok.vault.repository.*;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

/** Local fictional fixtures; existing rows and experiment changes survive restarts. */
@Component
public class DemoDataInitializer implements ApplicationRunner {
    private final OrganizationRepository organizations;
    private final UserRepository users;
    private final DocumentRepository documents;
    private final DocumentPermissionRepository permissions;
    private final PasswordEncoder encoder;

    public DemoDataInitializer(OrganizationRepository organizations, UserRepository users,
                               DocumentRepository documents, DocumentPermissionRepository permissions,
                               PasswordEncoder encoder) {
        this.organizations = organizations; this.users = users; this.documents = documents;
        this.permissions = permissions; this.encoder = encoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        Organization a = organization(1L, "Organization A");
        Organization b = organization(2L, "Organization B");
        VaultUser alice = user(1L, "alice", a, Role.EMPLOYEE);
        VaultUser bob = user(2L, "bob", a, Role.WORKSPACE_MANAGER);
        user(3L, "adminA", a, Role.ORGANIZATION_ADMIN);
        VaultUser charlie = user(4L, "charlie", b, Role.EMPLOYEE);
        VaultUser diana = user(5L, "diana", b, Role.WORKSPACE_MANAGER);
        Document one = document(1L, a, alice, "alice-notes.txt", "Alice's private notes from Organization A.");
        document(2L, a, bob, "bob-confidential.txt", "CONFIDENTIAL: Bob's budget document from Organization A.");
        Document three = document(3L, b, charlie, "charlie-confidential.txt", "CONFIDENTIAL: Organization B document owned by Charlie. Organization A has no access.");
        document(4L, b, diana, "diana-project.txt", "Diana's internal project plan from Organization B.");
        grantIfMissing(one, bob);
        grantIfMissing(three, diana);
    }

    private Organization organization(Long id, String name) {
        return organizations.findById(id).orElseGet(() -> organizations.save(new Organization(id, name)));
    }

    private VaultUser user(Long id, String username, Organization organization, Role role) {
        return users.findById(id).orElseGet(() -> users.save(new VaultUser(id, username,
                encoder.encode(username + "-demo"), organization, role)));
    }

    private Document document(Long id, Organization organization, VaultUser owner, String filename, String content) {
        return documents.findById(id).orElseGet(() -> {
            Document created = documents.save(new Document(id, organization, owner, filename, content,
                    Instant.parse("2026-01-01T12:00:00Z")));
            grantIfMissing(created, owner);
            return created;
        });
    }

    private void grantIfMissing(Document document, VaultUser user) {
        if (permissions.findByDocumentIdAndUserId(document.getId(), user.getId()).isEmpty()) {
            permissions.save(new DocumentPermission(document, user, Permission.MANAGE));
        }
    }
}
