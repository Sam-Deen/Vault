package nl.bok.vault.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "document_permissions", uniqueConstraints = @UniqueConstraint(columnNames = {"document_id", "user_id"}))
public class DocumentPermission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "document_id", nullable = false)
    private Document document;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private VaultUser user;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Permission permission;

    protected DocumentPermission() {}
    public DocumentPermission(Document document, VaultUser user, Permission permission) {
        if (!document.getOrganization().getId().equals(user.getOrganization().getId())) {
            throw new IllegalArgumentException("Permission recipient must belong to the document organization.");
        }
        this.document = document; this.user = user; this.permission = permission;
    }
    public Long getId() { return id; }
    public Document getDocument() { return document; }
    public VaultUser getUser() { return user; }
    public Permission getPermission() { return permission; }
    public void setPermission(Permission permission) { this.permission = permission; }
}
