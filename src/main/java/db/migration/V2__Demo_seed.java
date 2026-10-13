package db.migration;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.sql.Connection;

/** Runs once as the migration role, preserving existing rows and experiment grants. */
public class V2__Demo_seed extends BaseJavaMigration {
    @Override public void migrate(Context context) throws Exception { seed(context.getConnection()); }
    public static void seed(Connection connection) throws Exception {
        try (var statement = connection.createStatement()) {
            statement.executeUpdate("INSERT INTO organizations VALUES (1, 'Organization A'), (2, 'Organization B') ON CONFLICT (id) DO NOTHING");
        }
        String[] names = {"alice", "bob", "adminA", "charlie", "diana"};
        String[] roles = {"EMPLOYEE", "WORKSPACE_MANAGER", "ORGANIZATION_ADMIN", "EMPLOYEE", "WORKSPACE_MANAGER"};
        var encoder = new BCryptPasswordEncoder();
        for (int i = 0; i < names.length; i++) {
            try (var sql = connection.prepareStatement("INSERT INTO vault_users (id,username,password_hash,organization_id,role) VALUES (?,?,?,?,?) ON CONFLICT (id) DO NOTHING")) {
                sql.setLong(1, i + 1); sql.setString(2, names[i]); sql.setString(3, encoder.encode(names[i] + "-demo"));
                sql.setLong(4, i < 3 ? 1 : 2); sql.setString(5, roles[i]); sql.executeUpdate();
            }
        }
        String[] filenames = {"alice-notes.txt", "bob-confidential.txt", "charlie-confidential.txt", "diana-project.txt"};
        String[] contents = {"Alice's private notes from Organization A.", "CONFIDENTIAL: Bob's budget document from Organization A.",
            "CONFIDENTIAL: Organization B document owned by Charlie. Organization A has no access.", "Diana's internal project plan from Organization B."};
        long[] owners = {1,2,4,5};
        for (int i = 0; i < 4; i++) {
            try (var sql = connection.prepareStatement("INSERT INTO documents (id,organization_id,owner_id,filename,content,created_at) VALUES (?,?,?,?,?,TIMESTAMPTZ '2026-01-01 12:00:00+00') ON CONFLICT (id) DO NOTHING")) {
                sql.setLong(1,i+1); sql.setLong(2,i<2?1:2); sql.setLong(3,owners[i]);
                sql.setString(4,filenames[i]); sql.setString(5,contents[i]);
                // Only newly created documents receive an owner grant, matching the original initializer.
                if (sql.executeUpdate() == 1) { grant(connection,i+1,owners[i]); }
            }
        }
        grant(connection,1,2); grant(connection,3,5);
    }
    private static void grant(Connection connection, long document, long user) throws Exception {
        try (var sql = connection.prepareStatement("INSERT INTO document_permissions (document_id,user_id,permission) VALUES (?,?,'MANAGE') ON CONFLICT (document_id,user_id) DO NOTHING")) {
            sql.setLong(1,document); sql.setLong(2,user); sql.executeUpdate();
        }
    }
}
