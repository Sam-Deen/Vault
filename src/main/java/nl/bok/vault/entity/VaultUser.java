package nl.bok.vault.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "vault_users")
public class VaultUser {
    @Id
    private Long id;
    @Column(nullable = false, unique = true)
    private String username;
    @Column(nullable = false)
    private String passwordHash;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "organization_id", nullable = false)
    private Organization organization;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    protected VaultUser() {}
    public VaultUser(Long id, String username, String passwordHash, Organization organization, Role role) {
        this.id = id; this.username = username; this.passwordHash = passwordHash;
        this.organization = organization; this.role = role;
    }
    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public Organization getOrganization() { return organization; }
    public Role getRole() { return role; }
}
