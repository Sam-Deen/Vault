# Vault

A small Node.js security project using Express and PostgreSQL in Docker. It keeps
Argon2id passwords, TOTP sign-in, document permissions, envelope encryption,
parameterized filename search, security headers, rate limiting, document RLS,
and structured security logging.

`postgres-before-Vault` preserves the excessive-privilege baseline. `main` and
`postgres-Vault` use separate administration, application, and read-only accounts.
`rls-before-Vault` preserves document SELECT access across organizations;
`rls-Vault` and `main` add organization policies.
`logging-before-Vault` preserves the app before security logging;
`logging-Vault` and `main` include the logger.

## Start

Install Docker Desktop and Node.js 24.7 or newer. From this folder:

```sh
node scripts/generate-master-key.js
docker compose up --build -d --wait
```

Open `https://localhost:8443`. The app generates its development TLS certificate
inside Docker. HTTP on port 8080 redirects to HTTPS; HTTPS uses TLS 1.3.
PostgreSQL is available on `127.0.0.1:5432`. Nothing installs PostgreSQL on the host.
`API_PORT`, `HTTPS_PORT`, and `DB_PORT` can change the published ports.

Docker creates the schema, seeds encrypted demo data using the administration
account, then starts the app using `vault_app`. Database initialization consists of
plain SQL files in `db/`. There are no migration tables or upgrade steps.
When changing database versions or privilege snapshots, rebuild from scratch:

```sh
docker compose down -v
docker compose up --build -d --wait
```

This resets the demo database, TLS certificate, and security log volume. Keep `.env`, which holds
`DOCUMENT_MASTER_KEY`. Ordinary `docker compose down` preserves the data.

To use curl with the development certificate:

```sh
docker compose cp app:/app/certs/localhost.pem localhost.pem
curl --cacert localhost.pem https://127.0.0.1:8443/api/health
```

Use `curl.exe` in Windows PowerShell. Browser certificate trust is local to your
machine. Certificates and `.env` are ignored by Git.

## Demo accounts

Sign in with a password, scan the enrollment QR code, then enter its six-digit
authenticator code. Password-only sessions cannot access documents. Sessions expire
after 12 hours and reset on app restart; TOTP enrollment persists in PostgreSQL.

| ID | Username | Password | Organization | Role |
| --- | --- | --- | --- | --- |
| 1 | alice | alice-demo | A | EMPLOYEE |
| 2 | bob | bob-demo | A | WORKSPACE_MANAGER |
| 3 | adminA | adminA-demo | A | ORGANIZATION_ADMIN |
| 4 | charlie | charlie-demo | B | EMPLOYEE |
| 5 | diana | diana-demo | B | WORKSPACE_MANAGER |
| 6 | hashAlice | shared-demo | A | EMPLOYEE |
| 7 | hashBob | shared-demo | A | EMPLOYEE |

The last two users demonstrate that equal passwords have different salted hashes.

| Document | Filename | Organization | Owner | Initial MANAGE grants |
| --- | --- | --- | --- | --- |
| 1 | alice-notes.txt | A | alice | alice, bob |
| 2 | bob-confidential.txt | A | bob | bob |
| 3 | charlie-confidential.txt | B | charlie | charlie, diana |
| 4 | diana-project.txt | B | diana | diana |

Owners and workspace managers can read/manage within their own organization.
READ, WRITE, and MANAGE grants permit reading; only MANAGE permits grant changes.
Organization administrators have no automatic document access. Tenant/document
permissions remain in the application. PostgreSQL RLS additionally restricts
document rows to the authenticated user's organization.

## API

| Method | Route | Result |
| --- | --- | --- |
| GET | `/api/health` | Public `{"status":"UP"}` |
| POST | `/api/auth/login` | Username/password returns a pending bearer token |
| POST | `/api/auth/enroll` | Pending token returns QR code and manual secret |
| POST | `/api/auth/verify` | Pending token plus `{"code":"123456"}` returns a verified token |
| POST | `/api/auth/logout` | Revokes the bearer token |
| GET | `/api/documents` | Authorized metadata, sorted by ID |
| GET | `/api/documents/search?filename=alice` | Case-insensitive filename substring search |
| GET | `/api/documents/{id}` | Authorized metadata and decrypted content |
| GET | `/api/documents/{id}/permissions` | Grants, requiring document management |
| PUT | `/api/documents/{id}/permissions` | Creates/updates a grant, requiring document management |

Use `Authorization: Bearer <verified token>` on protected requests. PUT accepts
`{"userId":1,"permission":"MANAGE"}`; allowed values are READ, WRITE, MANAGE.
Successful JSON fields and demo document contents match the earlier snapshots.
Denied document reads return `404`; denied grant operations return `403`.
Validation errors return `400`, missing authentication `401`, and non-JSON PUT `415`.
Unexpected errors return generic problem JSON without SQL or stack traces.

Helmet adds CSP, HSTS, nosniff, frame protection, and referrer policy. All API
requests share a 30-request/IP/minute limit; excess requests return `429` with
`Retry-After`. Inspect headers on `/api/health`; send 31 requests in a fresh minute
to demonstrate the limit. Malformed JSON (`{`) posted to `/api/auth/login` returns
a safe `400` response.

## Encryption and search

Each document version has a random AES-256-GCM data key and random IV. The data key
is wrapped under `DOCUMENT_MASTER_KEY` with its own random IV. Ciphertext/tags live
in `documents`; wrapped keys/tags live in `document_keys`. The master key stays in
the environment. Only the current version is retained. Administrative seed/tests
can replace a version; the HTTP API has no content-editing route.

Inspect stored ciphertext without decrypting it:

```sh
docker compose exec app node scripts/prove-document-storage.js
```

Authorized API reads decrypt after authorization. Wrong keys and tampered records
fail authentication. Reopening with the same master key preserves existing data.
Keep that key to reopen encrypted documents.

Search binds its filename using PostgreSQL parameters. Alice searching `alice`
gets document 1; searching `' OR 1=1 --` gets `[]`. Apostrophes and `%`/`_` search
wildcards still work. `examples/search.postman_collection.json` contains both
requests; set its `baseUrl` and Alice's verified `token`.

## Database privilege experiment

| Account | Password | Secured access |
| --- | --- | --- |
| vault_admin | vault-admin-demo | Database administrator |
| vault_app | vault-app-demo | Read authentication/documents/keys/grants; update TOTP fields; insert/update grants |
| vault_readonly | vault-readonly-demo | Read organizations, encrypted documents, and grants |

The application account owns no tables and cannot create tables (including temporary
tables), schemas, databases, or roles. It cannot change role privileges, change
password/role columns, modify document/key records, or delete records. The read-only
account cannot write or read authentication records/wrapped keys. Administration
and seeding use `vault_admin`; the app receives only its own database connection.

Show the consequences using actual SQL queries:

```sh
docker compose run --rm seed node scripts/prove-database-roles.js
```

The script connects as each account and tests document reads, TOTP updates, table
creation, temporary table creation, role creation/changes, and deleting unrelated
records. Each statement runs inside BEGIN/ROLLBACK, preserving the data. On this
baseline all operations succeed for `vault_app`, demonstrating its excessive access.
On the secured snapshot, application reads/TOTP updates succeed while the five
administrative operations return `DENIED (42501)`. Read-only document reads succeed;
its writes and administrative operations return `DENIED (42501)`.

For a before/after comparison, stop and rebuild the database on each snapshot:

```sh
git switch postgres-before-Vault
docker compose down -v
docker compose up --build -d --wait
docker compose run --rm seed node scripts/prove-database-roles.js
```

```sh
git switch postgres-Vault
docker compose down -v
docker compose up --build -d --wait
docker compose run --rm seed node scripts/prove-database-roles.js
```

Example denied statements as `vault_app`:

```sql
CREATE TABLE privilege_probe (id integer);
CREATE ROLE extra_user;
ALTER ROLE vault_app SUPERUSER;
DELETE FROM organizations WHERE id = -1;
```

For interactive SQL, connect through TCP and enter the account password:

```sh
docker compose exec db psql -h 127.0.0.1 -U vault_app -d vault
```

## Row security experiment

Run the same read-only SQL probe on each snapshot after rebuilding the database:

```sh
git switch rls-before-Vault
docker compose down -v
docker compose up --build -d --wait
docker compose exec app node scripts/prove-row-security.js
```

Without RLS, `vault_readonly` reads documents 1–4 across organizations A and B,
even when the test transaction sets organization 1. Explicitly requesting
organization 2 also returns documents 3 and 4. SELECT permission alone does not
filter rows by organization.

Repeat on the secured snapshot:

```sh
git switch rls-Vault
docker compose down -v
docker compose up --build -d --wait
docker compose exec app node scripts/prove-row-security.js
```

| Query context | Without RLS | With RLS |
| --- | --- | --- |
| No organization | Documents 1–4 | No rows |
| Organization 1 (A) | Documents 1–4 | Documents 1–2 |
| Organization 1, explicitly query organization 2 | Documents 3–4 | No rows |
| Organization 2 (B) | Documents 1–4 | Documents 3–4 |

The probe connects as `vault_readonly`, issues actual SELECT statements without
application filters, and rolls back each transaction. It sets test contexts
explicitly to demonstrate the policy. The app instead takes the organization
from the database user associated with a verified bearer session. Query strings,
headers, and JSON bodies cannot choose that context.

Each protected operation checks out one connection, begins a transaction, and
binds `set_config('vault.organization_id', organization, true)`. All its queries
use that connection. Commit/rollback clears the transaction-local context.
The `documents` policy compares its organization column with that context;
an absent context returns no rows. App/read-only roles cannot bypass RLS.
The administrator retains access for seeding. Startup still authenticates stored
ciphertext in every organization. Existing per-document permission checks remain.

For an interactive comparison, connect as `vault_readonly` using the demo password:

```sh
docker compose exec db psql -h 127.0.0.1 -U vault_readonly -d vault
```

```sql
SELECT id, "organizationId", filename FROM documents ORDER BY id;
BEGIN;
SELECT set_config('vault.organization_id', '1', true);
SELECT id, "organizationId", filename FROM documents ORDER BY id;
SELECT id FROM documents WHERE "organizationId" = 2;
ROLLBACK;
```

## Security logging

Each incoming request receives a generated UUID in the `X-Request-Id` response
header. Client-supplied request IDs are ignored. Security events are one JSON
object per line in `logs/security.jsonl`, separate from API responses and normal
console output. Docker persists this file in `vault-security-logs`.
Local Node runs can change its path with `SECURITY_LOG_FILE`.

Every event includes UTC `timestamp`, `event`, `requestId`, HTTP `method`, route
template, response `status`, `userId`, and `organizationId`. Identity is `null`
when no trusted user identity is available. Document/permission events add `documentId`;
permission changes also include `targetUserId` and `permission` when valid.
Only these fields are accepted. Passwords, bearer tokens, TOTP codes/secrets,
document contents, request bodies, headers, and query strings are excluded.

| Action | Event | HTTP status |
| --- | --- | --- |
| Correct password, awaiting TOTP | `authentication.password_accepted` | 200 |
| Complete password/TOTP login | `authentication.succeeded` | 200 |
| Incorrect password | `authentication.failed` | 401 |
| Invalid TOTP code | `totp.failed` | 401 |
| Alice reads Organization B document 3 | `document.access_denied` | 404 |
| Alice changes Bob's document 2 permissions | `permission.modification_denied` | 403 |
| Alice grants READ on her document 1 | `permission.modified` | 200 |
| Exceed API request limit | `rate_limited` | 429 |

Import `examples/security-logging.postman_collection.json` into Postman and run
the collection, or use the installed Postman CLI. Use a fresh demo database so
the collection can enroll Alice, generate TOTP codes, and complete authentication.
The run then triggers each event and checks unique request IDs. The allowed
permission request grants `hashAlice` READ on Alice's document. The final request
repeats until the API returns 429. Allow the rate-limit window to reset before
another run. For an already enrolled Alice, set the collection's `totpSecret`
locally to her enrollment secret.

```sh
docker compose up --build -d --wait
postman collection run examples/security-logging.postman_collection.json --insecure --no-report-events
docker compose exec app cat logs/security.jsonl
```

`--insecure` accepts the local development certificate. In the Postman app,
disable certificate verification for this local run or trust its certificate.
Match each log's `requestId` with the response header or the collection's console
message. To watch new events, use `docker compose exec app tail -f logs/security.jsonl`.
For local Node execution, use `Get-Content logs/security.jsonl -Wait` in PowerShell.
Log files, certificates, and runtime authentication values are excluded from Git.

## Development and tests

For local Node execution with only PostgreSQL in Docker:

```sh
npm ci
docker compose up --build -d --wait db
npm run seed
npm run cert
npm start
```

Copy `.env.example` to `.env` before key generation if you want custom settings.
`DATABASE_URL` is the app connection; `ADMIN_DATABASE_URL` is used by seeding/proofs.
For tests, start the Docker database, then run:

```sh
npm test
```

Tests create and drop randomly named disposable PostgreSQL databases. They do not
reset the demo database. `TEST_ADMIN_DATABASE_URL` can select another test server.
Tests cover auth/TOTP, authorization, grants, search injection, encryption, version
transactions, persistence, headers, and rate limiting.
`node --test test/database-roles.test.js` checks the three accounts against real
SQL operations, including permitted grant insertion/updating and rejected table,
role, sensitive-column, deletion, and privilege-escalation operations.

Verification passed all 53 tests. Fresh Docker startup and real HTTPS checks also
passed password/TOTP authentication, document decryption, tenant isolation,
parameterized search, and permission insertion/updating under `vault_app`. The
before/after role probes confirmed administrative SQL changes from ALLOWED to
DENIED (`42501`) for the application account.
Row-security tests also check both SELECT roles, missing context, pooled connection
reuse, rollback, concurrent organizations, forged HTTP organization identifiers,
and startup rejection of damaged ciphertext in other organizations.
Logging tests check required events, response/log request-ID correlation, permitted
fields, and exclusion of actual passwords, tokens, TOTP secrets/codes, and contents.
The Postman logging collection passed 64 assertions against a fresh Docker stack;
the resulting log entries matched its request IDs and expected event/status fields.
