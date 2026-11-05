ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

CREATE POLICY document_organization ON documents
  USING ("organizationId" = NULLIF(current_setting('vault.organization_id', true), '')::bigint);
