package nl.bok.vault.integration;

import com.fasterxml.jackson.databind.JsonNode;
import db.migration.V2__Demo_seed;
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

/** Real HTTP authorization plus independent PostgreSQL RLS checks as the runtime role. */
@org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
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
        properties.add("spring.datasource.username", () -> "vault_app");
        properties.add("spring.datasource.password", () -> "vault-app-local-demo");
        properties.add("spring.flyway.url", postgres::getJdbcUrl);
        properties.add("spring.flyway.user", postgres::getUsername);
        properties.add("spring.flyway.password", postgres::getPassword);
        properties.add("spring.datasource.hikari.maximum-pool-size", () -> "1");
        properties.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
    }

    @Autowired TestRestTemplate http;
    @Autowired TransactionTemplate transactions;
    @Autowired DocumentPermissionRepository permissions;
    @Autowired DocumentRepository documents;
    @Autowired UserRepository users;
    @Autowired OrganizationRepository organizations;
    @Autowired JdbcTemplate runtime;
    JdbcTemplate jdbc;

    @BeforeEach
    void restoreFixtures() {
        jdbc = new JdbcTemplate(new org.springframework.jdbc.datasource.DriverManagerDataSource(
                postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword()));
        jdbc.execute("TRUNCATE document_permissions RESTART IDENTITY");
        jdbc.execute("INSERT INTO document_permissions (document_id,user_id,permission) VALUES "
                + "(1,1,'MANAGE'),(2,2,'MANAGE'),(3,4,'MANAGE'),(4,5,'MANAGE'),(1,2,'MANAGE'),(3,5,'MANAGE')");
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
    void mc1_crossTenantDocumentAccess_isPrevented() {
        for (long id : new long[]{3,4}) {
            var response = get("alice", "/api/documents/" + id);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getBody().toString()).doesNotContain("CONFIDENTIAL", "content", "filename", "organizationId");
        }
        assertThat(get("alice", "/api/documents").getBody()).hasSize(1);
    }

    @Test
    void mc1_individualDocumentPermissionChecks_areEnforced() {
        assertThat(storedPermissionCount(2, 1)).isZero();
        assertThat(get("alice", "/api/documents/2").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void mc2_unauthorizedPermissionModification_isPrevented() {
        assertThat(storedPermissionCount(2, 1)).isZero();
        assertThat(get("alice", "/api/documents/2/permissions").getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        var response = put("alice", 2, payload(1, "MANAGE"));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(storedPermissionCount(2, 1)).isZero();
        assertThat(get("alice", "/api/documents/2/permissions").getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(get("alice", "/api/documents").getBody()).hasSize(1);
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
        assertThat(put("bob", 2, payload(4, "MANAGE")).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
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
            "{\"userId\":1,\"permission\":\"OWNER\"}", "{\"userId\":1,\"permission\":null}",
            "{\"userId\":1,\"permission\":0}", "{\"userId\":1,\"permission\":2}", "{"})
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
        assertThat(get("bob", "/api/documents/999/permissions").getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(put("alice", 999, payload(1, "MANAGE")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(put("bob", 2, payload(999, "MANAGE")).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void seed_isIdempotentAndPreservesExperimentChanges() throws Exception {
        put("bob", 2, payload(1, "MANAGE"));
        try (var connection = jdbc.getDataSource().getConnection()) {
            V2__Demo_seed.seed(connection);
            V2__Demo_seed.seed(connection);
        }
        assertThat(organizations.count()).isEqualTo(2);
        assertThat(users.count()).isEqualTo(5);
        assertThat(jdbc.queryForObject("select count(*) from documents", Long.class)).isEqualTo(4);
        assertThat(jdbc.queryForObject("select count(*) from document_permissions", Long.class)).isEqualTo(7);
        assertThat(storedPermission(2, 1)).isEqualTo(Permission.MANAGE.name());
    }

    @Test
    void passwords_areBcryptHashesAndOwnerPermissionsAreSeeded() {
        assertThat(jdbc.queryForList("select password_hash from vault_users", String.class))
                .hasSize(5).allMatch(hash -> hash.startsWith("$2a$") && hash.length() == 60);
        for (long[] pair : new long[][]{{1, 1}, {2, 2}, {3, 4}, {4, 5}}) {
            assertThat(storedPermission(pair[0], pair[1])).isEqualTo("MANAGE");
        }
        assertThat(jdbc.queryForObject("select count(*) from document_permissions", Long.class)).isEqualTo(6);
    }

    @ParameterizedTest
    @CsvSource({"charlie,3,1", "diana,4,2", "bob,2,3", "adminA,1,4"})
    void tenantAndAdministratorIsolation(String user, long own, long foreign) {
        assertThat(get(user, "/api/documents/" + own).getStatusCode())
                .isEqualTo(user.equals("adminA") ? HttpStatus.NOT_FOUND : HttpStatus.OK);
        assertThat(get(user, "/api/documents/" + foreign).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void explicitManageAllowsManagementButReadAndWriteCannotEscalate() {
        for (String permission : new String[]{"READ","WRITE"}) {
            put("bob", 2, payload(1,permission));
            assertThat(get("alice", "/api/documents/2").getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(put("alice",2,payload(1,"MANAGE")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(storedPermission(2,1)).isEqualTo(permission);
        }
        put("bob",2,payload(1,"MANAGE"));
        assertThat(put("alice",2,payload(3,"READ")).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(get("adminA","/api/documents/2").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(put("adminA",2,payload(3,"MANAGE")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void ownersAndBothWorkspaceManagersRetainLegitimateManagement() {
        assertThat(put("alice",1,payload(3,"READ")).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(put("diana",3,payload(5,"WRITE")).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(put("diana",1,payload(1,"READ")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(storedPermission(1,1)).isEqualTo("MANAGE");
    }

    @Test
    void rlsNativeQueriesWithoutTenantPredicateAreIsolatedAndFailClosed() {
        assertThat(runtime.queryForObject("select count(*) from documents", Integer.class)).isZero();
        assertThat(runtime.queryForObject("select count(*) from document_permissions", Integer.class)).isZero();
        transactions.executeWithoutResult(status -> {
            tenant(1);
            assertThat(runtime.queryForList("select id from documents order by id", Long.class)).containsExactly(1L,2L);
            assertThat(runtime.queryForList("select distinct document_id from document_permissions order by document_id", Long.class)).containsExactly(1L,2L);
            assertThat(runtime.queryForObject("select count(*) from documents where id=3", Integer.class)).isZero();
            assertThat(runtime.update("update document_permissions set permission='READ' where document_id=3")).isZero();
        });
        assertThat(runtime.queryForObject("select count(*) from documents", Integer.class)).isZero();
        transactions.executeWithoutResult(status -> {
            tenant(2);
            assertThat(runtime.queryForList("select id from documents order by id", Long.class)).containsExactly(3L,4L);
            status.setRollbackOnly();
        });
        assertThat(runtime.queryForObject("select count(*) from documents", Integer.class)).isZero();
        assertThat(storedPermission(3,4)).isEqualTo("MANAGE");
    }

    @Test
    void rlsRejectsMissingAndCrossTenantInserts() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> runtime.update(
                "insert into document_permissions(document_id,user_id,permission) values(2,1,'MANAGE')"))
                .isInstanceOf(org.springframework.dao.DataAccessException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> transactions.executeWithoutResult(status -> {
            tenant(1);
            runtime.update("insert into document_permissions(document_id,user_id,permission) values(3,1,'MANAGE')");
        })).isInstanceOf(org.springframework.dao.DataAccessException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> transactions.executeWithoutResult(status -> {
            tenant(1);
            runtime.update("insert into document_permissions(document_id,user_id,permission) values(2,4,'MANAGE')");
        })).isInstanceOf(org.springframework.dao.DataAccessException.class);
        assertThat(storedPermissionCount(2,1)).isZero();
        assertThat(storedPermissionCount(3,1)).isZero();
        assertThat(storedPermissionCount(2,4)).isZero();
    }

    @Test
    void singlePooledConnectionDoesNotLeakTenantAcrossSuccessAndDenial() {
        Integer pid = runtime.queryForObject("select pg_backend_pid()", Integer.class);
        for (int i=0; i<3; i++) {
            assertThat(get("alice","/api/documents").getBody()).hasSize(1);
            assertThat(get("diana","/api/documents").getBody()).hasSize(2);
            assertThat(put("alice",2,payload(1,"MANAGE")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(runtime.queryForObject("select count(*) from documents", Integer.class)).isZero();
        }
        assertThat(runtime.queryForObject("select pg_backend_pid()", Integer.class)).isEqualTo(pid);
    }

    @Test
    void runtimeRoleCannotBypassRlsOrChangeSchema() {
        assertThat(runtime.queryForObject("select rolsuper or rolbypassrls or rolcreaterole from pg_roles where rolname=current_user", Boolean.class)).isFalse();
        assertThat(runtime.queryForObject("select has_schema_privilege(current_user,'public','CREATE')", Boolean.class)).isFalse();
        assertThat(runtime.queryForObject("select count(*) from pg_class where relname in ('documents','document_permissions') and relowner=(select oid from pg_roles where rolname=current_user)", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from flyway_schema_history where success and version in ('1','2','3','4')", Integer.class)).isEqualTo(4);
    }

    @Test
    void auditLogsDenialsAfterRollbackAndSuccessAfterCommit(org.springframework.boot.test.system.CapturedOutput output) {
        get("alice","/api/documents/3");
        put("alice",2,payload(1,"MANAGE"));
        put("bob",2,payload(1,"READ"));
        assertThat(output.getOut()).contains("operation=DOCUMENT_READ", "operation=PERMISSION_UPDATE",
                "documentId=3", "documentId=2", "result=denied", "result=allowed", "timestamp=", "userId=");
        assertThat(output.getOut()).doesNotContain("alice-demo", "bob-demo", "Authorization: Basic",
                "CONFIDENTIAL: Organization B");
    }

    private void tenant(long organization) {
        runtime.queryForObject("select set_config('vault.organization_id',?,true)",String.class,Long.toString(organization));
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
