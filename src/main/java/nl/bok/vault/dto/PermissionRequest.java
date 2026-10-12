package nl.bok.vault.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import nl.bok.vault.entity.Permission;

public record PermissionRequest(@NotNull @Positive Long userId, @NotNull Permission permission) {}
