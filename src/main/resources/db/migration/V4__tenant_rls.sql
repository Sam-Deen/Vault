REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO vault_app;
GRANT SELECT ON organizations, vault_users, documents, document_permissions TO vault_app;
GRANT INSERT, UPDATE ON document_permissions TO vault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vault_app;
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
ALTER TABLE document_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY document_tenant ON documents TO vault_app
 USING (organization_id = nullif(current_setting('vault.organization_id', true), '')::bigint)
 WITH CHECK (organization_id = nullif(current_setting('vault.organization_id', true), '')::bigint);
CREATE POLICY permission_tenant ON document_permissions TO vault_app
 USING (EXISTS (SELECT 1 FROM public.documents d WHERE d.id = document_id
   AND d.organization_id = nullif(current_setting('vault.organization_id', true), '')::bigint))
 WITH CHECK (EXISTS (SELECT 1 FROM public.documents d JOIN public.vault_users u
   ON u.organization_id = d.organization_id WHERE d.id = document_id AND u.id = user_id
   AND d.organization_id = nullif(current_setting('vault.organization_id', true), '')::bigint));
