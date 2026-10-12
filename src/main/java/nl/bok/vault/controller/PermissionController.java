package nl.bok.vault.controller;

import nl.bok.vault.dto.PermissionResponse;
import nl.bok.vault.service.PermissionService;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/documents/{id}/permissions")
public class PermissionController {
    private final PermissionService permissions;
    public PermissionController(PermissionService permissions) { this.permissions = permissions; }

    @GetMapping
    public List<PermissionResponse> list(@PathVariable Long id) { return permissions.list(id); }
}
