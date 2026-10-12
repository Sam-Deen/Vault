package nl.bok.vault.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "organizations")
public class Organization {
    @Id
    private Long id;
    @Column(nullable = false)
    private String name;

    protected Organization() {}
    public Organization(Long id, String name) { this.id = id; this.name = name; }
    public Long getId() { return id; }
    public String getName() { return name; }
}
