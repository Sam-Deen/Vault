package nl.bok.vault.integration;

import db.migration.V2__Demo_seed;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import java.sql.DriverManager;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class MigrationCompatibilityTest {
    @Container static final PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:17.11-alpine");

    @Test void adoptsExistingHibernateSchemaWithoutDeletingData() throws Exception {
        try (var connection = DriverManager.getConnection(postgres.getJdbcUrl(),postgres.getUsername(),postgres.getPassword());
             var statement = connection.createStatement();
             var schema = getClass().getResourceAsStream("/db/migration/V1__schema.sql")) {
            statement.execute(new String(schema.readAllBytes(),StandardCharsets.UTF_8));
            V2__Demo_seed.seed(connection);
            statement.executeUpdate("INSERT INTO document_permissions(document_id,user_id,permission) VALUES(2,1,'MANAGE')");
            statement.executeUpdate("UPDATE documents SET content='Existing custom content' WHERE id=2");
        }
        var flyway = Flyway.configure().dataSource(postgres.getJdbcUrl(),postgres.getUsername(),postgres.getPassword())
                .baselineOnMigrate(true).baselineVersion("0")
                .placeholders(Map.of("runtimePassword","vault-app-local-demo")).load();
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(4);
        assertThat(flyway.migrate().migrationsExecuted).isZero();
        try (var connection = DriverManager.getConnection(postgres.getJdbcUrl(),postgres.getUsername(),postgres.getPassword());
             var statement = connection.createStatement()) {
            try (var rows = statement.executeQuery("SELECT content FROM documents WHERE id=2")) {
                rows.next(); assertThat(rows.getString(1)).isEqualTo("Existing custom content");
            }
            try (var rows = statement.executeQuery("SELECT count(*) FROM document_permissions WHERE document_id=2 AND user_id=1 AND permission='MANAGE'")) {
                rows.next(); assertThat(rows.getInt(1)).isEqualTo(1);
            }
        }
        try (var connection = DriverManager.getConnection(postgres.getJdbcUrl(),"vault_app","vault-app-local-demo");
             var statement = connection.createStatement();
             var rows = statement.executeQuery("SELECT count(*) FROM documents")) {
            rows.next(); assertThat(rows.getInt(1)).isZero();
        }
    }
}
