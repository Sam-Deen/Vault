package nl.bok.vault.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Fail startup rather than silently running with an RLS-bypassing account. */
@Component
public class RuntimeDatabaseGuard implements ApplicationRunner {
    private final JdbcTemplate jdbc;
    public RuntimeDatabaseGuard(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    @Override public void run(ApplicationArguments args) {
        Boolean safe = jdbc.queryForObject("""
            SELECT current_user = 'vault_app' AND NOT rolsuper AND NOT rolbypassrls
                AND NOT rolcreaterole AND NOT rolcreatedb
                AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
                AND NOT EXISTS (SELECT FROM pg_auth_members WHERE member = r.oid)
                AND (SELECT count(*) = 2 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname IN ('documents','document_permissions')
                    AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner <> r.oid
                    AND NOT has_table_privilege(current_user, c.oid, 'TRUNCATE'))
            FROM pg_roles r WHERE rolname = current_user
            """, Boolean.class);
        if (!Boolean.TRUE.equals(safe)) { throw new IllegalStateException("Unsafe runtime database role or missing RLS"); }
    }
}
