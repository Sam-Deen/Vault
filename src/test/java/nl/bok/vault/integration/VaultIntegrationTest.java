package nl.bok.vault.integration;

import com.fasterxml.jackson.databind.JsonNode;
import nl.bok.vault.config.DemoDataInitializer;
import nl.bok.vault.entity.Permission;
import nl.bok.vault.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;

/** Real HTTP, Spring Security and PostgreSQL; successful misuse cases are the baseline. */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"debug=false", "logging.level.root=INFO"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class VaultIntegrationTest {
    @Container
    static final PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:17.11-alpine");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", postgres::getJdbcUrl);
        properties.add("spring.datasource.username", postgres::getUsername);
        properties.add("spring.datasource.password", postgres::getPassword);
        properties.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    }

    @Autowired TestRestTemplate http;
    @Autowired TransactionTemplate transactions;
    @Autowired DemoDataInitializer seed;
    @Autowired DocumentPermissionRepository permissions;
    @Autowired DocumentRepository documents;
    @Autowired UserRepository users;
    @Autowired OrganizationRepository organizations;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach
    void restoreFixtures() {
        transactions.executeWithoutResult(status -> {
            permissions.deleteAllInBatch();
            documents.deleteAllInBatch();
            users.deleteAllInBatch();
            organizations.deleteAllInBatch();
            seed.run(null);
        });
    }

    @Test
    void health_isPublic() {
        var response = request(null, null, HttpMethod.GET, "/api/health", null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().path("status").asText()).isEqualTo("UP");
    }

    @ParameterizedTest
    @CsvSource({"GET,/api/documents", "GET,/api/documents/1", "GET,/api/documents/1/permissions",
            "PUT,/api/documents/1/permissions"})
    void protectedEndpoints_requireAuthentication(String method, String path) {
        var response = request(null, null, HttpMethod.valueOf(method), path,
                method.equals("PUT") ? payload(1, "MANAGE") : null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Basic");
    }

    @ParameterizedTest
    @CsvSource({"alice,wrong-password", "missing,alice-demo"})
    void invalidCredentials_areRejected(String username, String password) {
        assertThat(request(username, password, HttpMethod.GET, "/api/documents", null).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void alice_canRetrieveOwnedDocument() {
        var response = get("alice", "/api/documents/1");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().path("filename").asText()).isEqualTo("alice-notes.txt");
        assertThat(response.getBody().has("passwordHash")).isFalse();
    }

    @Test
    void alice_listingContainsOnlyAuthorizedDocumentsInHerOrganization() {
        var response = get("alice", "/api/documents");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).path("id").asLong()).isEqualTo(1);
        assertThat(response.getBody().get(0).path("organizationId").asLong()).isEqualTo(1);
        assertThat(response.getBody().get(0).has("content")).isFalse();
    }

    @Test
    void bob_canReadAndManageDocumentTwo() {
        assertThat(get("bob", "/api/documents/2/permissions").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(put("bob", 2, payload(1, "READ")).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(storedPermission(2, 1)).isEqualTo("READ");
    }

    @Test
    void workspaceManager_canManageOwnWorkspaceWithoutExplicitPermission() {
        jdbc.update("delete from document_permissions where document_id = 1 and user_id = 2");
        assertThat(get("bob", "/api/documents/1/permissions").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(get("bob", "/api/documents").getBody()).hasSize(2);
    }

    @ParameterizedTest
    @CsvSource({"alice,2", "alice,3", "bob,3", "charlie,1", "diana,2", "adminA,1"})
    void securedPermissionReading_deniesUnauthorizedUsers(String username, long documentId) {
        assertThat(get(username, "/api/documents/" + documentId + "/permissions").getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void organizationAdministrator_hasNoAutomaticDocumentAccess() {
        var response = get("adminA", "/api/documents");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"READ", "WRITE"})
    void explicitReadOrWritePermission_allowsListingButNotManagement(String permission) {
        assertThat(put("bob", 2, payload(1, permission)).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(get("alice", "/api/documents").getBody()).hasSize(2);
        assertThat(get("alice", "/api/documents/2/permissions").getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void mc1_crossTenantDocumentAccess_isVulnerable() {
        var response = get("alice", "/api/documents/3");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().path("organizationId").asLong()).isEqualTo(2);
        assertThat(response.getBody().path("content").asText()).contains("CONFIDENTIAL", "Organization B");
        assertThat(get("alice", "/api/documents").getBody()).hasSize(1);
    }

    @Test
    void mc1_alsoOmitsIndividualDocumentPermissionChecks() {
        assertThat(storedPermissionCount(2, 1)).isZero();
        assertThat(get("alice", "/api/documents/2").getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void mc2_unauthorizedPermissionModification_isVulnerable() {
        assertThat(storedPermissionCount(2, 1)).isZero();
        assertThat(get("alice", "/api/documents/2/permissions").getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        var response = put("alice", 2, payload(1, "MANAGE"));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().path("permission").asText()).isEqualTo("MANAGE");
        // A direct SQL read proves a committed change outside the request's persistence context.
        assertThat(storedPermission(2, 1)).isEqualTo("MANAGE");
        assertThat(get("alice", "/api/documents/2/permissions").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(get("alice", "/api/documents").getBody()).hasSize(2);
    }

    @Test
    void permissionUpdates_updateExistingRowWithoutDuplicates() {
        var first = put("bob", 2, payload(1, "READ"));
        var second = put("bob", 2, payload(1, "WRITE"));
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(second.getBody().path("id")).isEqualTo(first.getBody().path("id"));
        assertThat(storedPermissionCount(2, 1)).isEqualTo(1);
        assertThat(storedPermission(2, 1)).isEqualTo("WRITE");
    }

    @Test
    void crossOrganizationRecipient_isRejectedWithoutPersisting() {
        assertThat(put("alice", 2, payload(4, "MANAGE")).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(storedPermissionCount(2, 4)).isZero();
    }

    @Test
    void crossOrganizationRequester_isRejectedEvenWithNativeRecipient() {
        assertThat(put("alice", 3, payload(4, "READ")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(storedPermission(3, 4)).isEqualTo("MANAGE");
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"userId\":1}", "{\"permission\":\"READ\"}",
            "{\"userId\":0,\"permission\":\"READ\"}", "{\"userId\":-1,\"permission\":\"READ\"}",
            "{\"userId\":1,\"permission\":\"OWNER\"}", "{\"userId\":1,\"permission\":null}", "{"})
    void invalidPayload_isRejected(String payload) {
        assertThat(put("alice", 2, payload).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(storedPermissionCount(2, 1)).isZero();
    }

    @Test
    void nonJsonMutation_isRejected() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("alice", "alice-demo");
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        var response = http.exchange("/api/documents/2/permissions", HttpMethod.PUT,
                new HttpEntity<>("userId=1&permission=MANAGE", headers), JsonNode.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
    }

    @Test
    void missingDocumentOrRecipient_returnsNotFound() {
        assertThat(get("alice", "/api/documents/999").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(get("bob", "/api/documents/999/permissions").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(put("alice", 999, payload(1, "MANAGE")).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(put("alice", 2, payload(999, "MANAGE")).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void seed_isIdempotentAndPreservesExperimentChanges() {
        put("alice", 2, payload(1, "MANAGE"));
        seed.run(null);
        seed.run(null);
        assertThat(organizations.count()).isEqualTo(2);
        assertThat(users.count()).isEqualTo(5);
        assertThat(documents.count()).isEqualTo(4);
        assertThat(permissions.count()).isEqualTo(7);
        assertThat(storedPermission(2, 1)).isEqualTo(Permission.MANAGE.name());
    }

    @Test
    void passwords_areBcryptHashesAndOwnerPermissionsAreSeeded() {
        assertThat(jdbc.queryForList("select password_hash from vault_users", String.class))
                .hasSize(5).allMatch(hash -> hash.startsWith("$2a$") && hash.length() == 60);
        for (long[] pair : new long[][]{{1, 1}, {2, 2}, {3, 4}, {4, 5}}) {
            assertThat(storedPermission(pair[0], pair[1])).isEqualTo("MANAGE");
        }
        assertThat(permissions.count()).isEqualTo(6);
    }

    private ResponseEntity<JsonNode> get(String username, String path) {
        return request(username, username + "-demo", HttpMethod.GET, path, null);
    }

    private ResponseEntity<JsonNode> put(String username, long documentId, String body) {
        return request(username, username + "-demo", HttpMethod.PUT,
                "/api/documents/" + documentId + "/permissions", body);
    }

    private ResponseEntity<JsonNode> request(String username, String password, HttpMethod method, String path, String body) {
        HttpHeaders headers = new HttpHeaders();
        if (username != null) { headers.setBasicAuth(username, password); }
        headers.setContentType(MediaType.APPLICATION_JSON);
        return http.exchange(path, method, new HttpEntity<>(body, headers), JsonNode.class);
    }

    private String payload(long userId, String permission) {
        return "{\"userId\":" + userId + ",\"permission\":\"" + permission + "\"}";
    }

    private String storedPermission(long documentId, long userId) {
        return jdbc.queryForObject("select permission from document_permissions where document_id = ? and user_id = ?",
                String.class, documentId, userId);
    }

    private int storedPermissionCount(long documentId, long userId) {
        return jdbc.queryForObject("select count(*) from document_permissions where document_id = ? and user_id = ?",
                Integer.class, documentId, userId);
    }
}
