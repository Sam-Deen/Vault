REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO vault_app, vault_readonly;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO vault_app, vault_readonly;

GRANT SELECT ON users, documents, permissions, document_keys TO vault_app;
GRANT UPDATE ("totpSecret", "pendingTotpSecret") ON users TO vault_app;
GRANT INSERT ("documentId", "userId", permission), UPDATE (permission) ON permissions TO vault_app;

GRANT SELECT ON organizations, documents, permissions TO vault_readonly;
