package nl.bok.vault.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "documents")
public class Document {
    @Id
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "organization_id", nullable = false)
    private Organization organization;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private VaultUser owner;
    @Column(nullable = false)
    private String filename;
    @Column(nullable = false, columnDefinition = "text")
    private String content;
    @Column(nullable = false)
    private Instant createdAt;

    protected Document() {}
    public Document(Long id, Organization organization, VaultUser owner, String filename, String content, Instant createdAt) {
        if (!organization.getId().equals(owner.getOrganization().getId())) {
            throw new IllegalArgumentException("Document owner must belong to the document organization.");
        }
        this.id = id; this.organization = organization; this.owner = owner;
        this.filename = filename; this.content = content; this.createdAt = createdAt;
    }
    public Long getId() { return id; }
    public Organization getOrganization() { return organization; }
    public VaultUser getOwner() { return owner; }
    public String getFilename() { return filename; }
    public String getContent() { return content; }
    public Instant getCreatedAt() { return createdAt; }
}
