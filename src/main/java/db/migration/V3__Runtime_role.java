package db.migration;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

/** Role provisioning is administrator-only; PostgreSQL format safely quotes the password. */
public class V3__Runtime_role extends BaseJavaMigration {
    @Override public void migrate(Context context) throws Exception {
        var connection = context.getConnection();
        try (var sql = connection.createStatement()) {
            sql.execute("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault_app') THEN CREATE ROLE vault_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; END $$");
            sql.execute("ALTER ROLE vault_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT");
        }
        String password = context.getConfiguration().getPlaceholders().get("runtimePassword");
        if (password == null || password.isBlank()) { throw new IllegalArgumentException("Runtime password required"); }
        try (var sql = connection.prepareStatement("SELECT format('ALTER ROLE vault_app PASSWORD %L', ?::text)")) {
            sql.setString(1,password);
            try (var result = sql.executeQuery()) {
                result.next();
                try (var command = connection.createStatement()) { command.execute(result.getString(1)); }
            }
        }
    }
}
