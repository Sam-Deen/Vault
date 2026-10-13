package nl.bok.vault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VaultApplication {
    public static void main(String[] args) {
        if ("true".equals(System.getenv("VAULT_MIGRATE_ONLY"))) {
            org.flywaydb.core.Flyway.configure()
                    .dataSource(System.getenv("DB_URL"), System.getenv("MIGRATION_USERNAME"), System.getenv("MIGRATION_PASSWORD"))
                    .baselineOnMigrate(true).baselineVersion("0")
                    .placeholders(java.util.Map.of("runtimePassword", System.getenv("DB_PASSWORD")))
                    .load().migrate();
            return;
        }
        SpringApplication.run(VaultApplication.class, args);
    }
}
