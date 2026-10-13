package nl.bok.vault.service;

import nl.bok.vault.entity.VaultUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import java.time.Instant;

/** Application logging survives database rollback; no request bodies or credentials. */
@Component
public class SecurityAudit {
    private static final Logger LOG = LoggerFactory.getLogger("vault.security.audit");
    public void record(VaultUser user, String operation, Long documentId, String result, String reason) {
        LOG.atInfo().addKeyValue("timestamp", Instant.now()).addKeyValue("userId", user.getId())
                .addKeyValue("operation", operation).addKeyValue("documentId", documentId)
                .addKeyValue("result", result).addKeyValue("reason", reason).log("security_audit");
    }
}
