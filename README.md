# Vault: secured authorization experiments

Vault is a local Spring Boot document collaboration prototype for a Security Engineering Body of Knowledge project. The implementation on `main` prevents MC1 (unauthorized document retrieval) and MC2 (unauthorized permission modification). The vulnerable baseline remains preserved in Git. Original evidence and secured instructions are in [SECURITY_EXPERIMENTS.md](SECURITY_EXPERIMENTS.md).

## Start and test

Start Docker Desktop, then run from this directory:

```sh
docker compose up --build -d --wait
docker compose ps
curl -i http://127.0.0.1:8080/api/health
```

On Windows PowerShell use `curl.exe`. The API listens on `http://127.0.0.1:8080`; PostgreSQL has no published port. The `migrate` container applies Flyway migrations and exits successfully before `app` starts. The app receives only restricted database credentials; its environment contains no migration password.

Run the complete build and tests with Java 21 or newer, Maven and a running Docker engine:

```sh
mvn -B -ntp verify
```

Tests use disposable PostgreSQL containers, restricted runtime connections for HTTP/RLS, and administrator connections for fixture reset and committed-state assertions. Independent application tests use an unfiltered repository. Migration tests verify preservation of an existing schema, content and grants.

```sh
docker compose logs app migrate db
docker compose restart app
docker compose up -d --wait
docker compose down
```

`down` preserves data. To intentionally erase **all local demonstration data**, use `docker compose down -v`, then the start command. Do not reset data you need to keep.

## Accounts and fixtures

| ID | Username | Password | Organization | Role |
| --- | --- | --- | --- | --- |
| 1 | alice | alice-demo | A (1) | EMPLOYEE |
| 2 | bob | bob-demo | A (1) | WORKSPACE_MANAGER |
| 3 | adminA | adminA-demo | A (1) | ORGANIZATION_ADMIN |
| 4 | charlie | charlie-demo | B (2) | EMPLOYEE |
| 5 | diana | diana-demo | B (2) | WORKSPACE_MANAGER |

Documents 1/2 belong to A and are owned by Alice/Bob; documents 3/4 belong to B and are owned by Charlie/Diana. Fresh fixtures contain 2 organizations, 5 users, 4 documents and 6 permissions: owners have MANAGE, Bob has MANAGE on document 1, and Diana has MANAGE on document 3. Alice has no document 2 permission. Passwords are BCrypt hashes. Migration preserves existing rows; seeding runs once under the migration account.

## API

All document endpoints require stateless HTTP Basic. Missing/invalid credentials return `401`. URLs, methods, JSON payloads and successful DTOs remain unchanged.

| Endpoint | Policy |
| --- | --- |
| `GET /api/health` | Public `200`, `{"status":"UP"}` |
| `GET /api/documents` | `200`, readable documents in the authenticated user's organization |
| `GET /api/documents/{id}` | Owner, explicit READ/WRITE/MANAGE or own organization's workspace manager; otherwise `404` |
| `GET /api/documents/{id}/permissions` | Owner, explicit MANAGE or own organization's workspace manager; otherwise `403` |
| `PUT /api/documents/{id}/permissions` | Same management policy and same-organization recipient; otherwise `403` |

Administrators receive no automatic document access. Document GET consistently returns `404` for missing and unauthorized targets without document metadata/content. Permission endpoints return `403` for missing, invisible and unauthorized targets to avoid distinguishing existence.

```sh
curl -i -u alice:alice-demo http://127.0.0.1:8080/api/documents/1
curl -i -u alice:alice-demo http://127.0.0.1:8080/api/documents/3
curl -i -u alice:alice-demo -X PUT -H "Content-Type: application/json" --data-binary '@examples/grant-alice-manage.json' http://127.0.0.1:8080/api/documents/2/permissions
```

Expected on clean fixtures: `200`, `404`, `403`. The unchanged attack body is `{"userId":1,"permission":"MANAGE"}`. Bob can submit it successfully because he owns/manages document 2. That grant authorizes Alice; remove it explicitly before repeating the unauthorized experiment.

Allowed permissions: READ, WRITE, MANAGE. Missing/null fields, nonpositive IDs, numeric/unknown enums or malformed JSON return `400`; non-JSON PUT returns `415`. After management authorization, foreign recipients return `400`, missing recipients `404`, and conflicting inserts `409`.

## Database configuration and upgrades

Copy `.env.example` to `.env` if needed. Defaults are fictional local credentials.

| Variable | Default | Purpose |
| --- | --- | --- |
| `MIGRATION_USERNAME` | vault | PostgreSQL administrator/migration account |
| `MIGRATION_PASSWORD` | vault-local-demo | Original administrator password |
| `DB_PASSWORD` | vault-app-local-demo | Restricted vault_app runtime password |
| `API_PORT` | 8080 | Compose host port |
| `DB_URL` | jdbc:postgresql://localhost:5432/vault | Direct Java connection; Compose supplies its internal URL |
| `DB_USERNAME` | vault_app | Direct Java runtime account; fixed in Compose |
| `FLYWAY_ENABLED` | true | Direct Java migrations; disabled in Compose app |
| `SERVER_ADDRESS` | 127.0.0.1 | Direct Java bind address |
| `SERVER_PORT` | 8080 | Internal API port |

For existing volumes, set migration variables to the original PostgreSQL credentials. Move an old `.env` administrator `DB_USERNAME`/`DB_PASSWORD` into `MIGRATION_USERNAME`/`MIGRATION_PASSWORD` and choose a separate runtime password. The runtime role is fixed to `vault_app`. Changing an environment variable does not rotate an existing role password: use administrator-controlled `ALTER ROLE` and update its runtime secret together.

Flyway baselines existing nonempty schemas at version **0** and then runs V1–V4. V1 creates missing baseline tables; V2 seeds missing fixtures; V3 provisions runtime; V4 enables/forces tenant RLS. Hibernate only validates. Migration requires role-creation rights and ownership of existing tables (the original Compose account has these). Incompatible custom schemas fail validation; back up and inspect instead of deleting data.

Direct `mvn spring-boot:run` uses separate Flyway and runtime connections in one local process. Production should migrate separately and run with `FLYWAY_ENABLED=false`, keeping migration secrets outside runtime as Compose does.

## Security controls and limitations

`CurrentUser.get` resolves the organization from authenticated identity and trusted database records, then sets a bound transaction-local `vault.organization_id` through JPA. Client tenant identifiers are never used. Document/permission RLS fails closed without context; permission writes also check recipient organization. RLS enforces tenant isolation; `DocumentAuthorization` enforces individual read/management rules. See [PostgreSQL RLS documentation](https://www.postgresql.org/docs/17/ddl-rowsecurity.html).

`vault_app` has no table ownership, superuser/BYPASSRLS, role creation, schema CREATE or TRUNCATE. `RuntimeDatabaseGuard` rejects unsafe configuration. User/organization tables remain readable for authentication/identity resolution but are not writable by runtime. Runtime may read documents and insert/update permissions within RLS scope.

Structured `vault.security.audit` logs contain timestamp, user ID, operation, document ID, result and reason. Denied reads and unauthorized updates survive rollback; successful changes log after commit. Credentials, headers and document contents are excluded.

HTTP Basic substitutes for intended production OIDC/MFA. Use fictional data locally. Production requires TLS, managed secrets, durable audit collection/retention, rate limits and stronger operational controls. One organization represents one workspace. Arbitrary SQL execution or compromised runtime credentials can change the custom tenant setting; RLS guards omitted predicates, not full application compromise. Global authentication records are outside document RLS. External sharing, malware scanning, object storage, versioning and encryption/KMS are not implemented.
