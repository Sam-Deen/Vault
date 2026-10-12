package nl.bok.vault.controller;

import nl.bok.vault.dto.DocumentSummary;
import nl.bok.vault.service.DocumentService;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {
    private final DocumentService documents;
    public DocumentController(DocumentService documents) { this.documents = documents; }

    @GetMapping
    public List<DocumentSummary> list() { return documents.listAccessible(); }
}
