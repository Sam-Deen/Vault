# Vault

A small Node.js document API for a school security project. `main` and
`Secured-Vault` fix two authorization vulnerabilities; `Vulnerable-Vault` preserves
both attacks. Use fictional data and run it locally.

The API uses [Express](https://expressjs.com/en/5x/api/), Node's built-in
[SQLite](https://nodejs.org/docs/latest-v24.x/api/sqlite.html), Argon2id password hashing,
and the built-in test runner. Express serves the API and small browser UI; `qrcode`
generates authenticator enrollment images.

## Run

Install Node.js 24.7 or newer, then:

```sh
npm ci
npm run keygen
npm run cert
npm start
```

Open `https://localhost:8443` for the minimal browser UI. All HTTP requests on port
8080 redirect to HTTPS with status `308`, preserving the method, path, and query.
HTTPS accepts TLS 1.3 only. `npm run cert` requires OpenSSL (Git for Windows works)
and generates a self-signed certificate for `localhost`, `127.0.0.1`, and `::1`.
Accept the browser's certificate warning for local development, or trust the
certificate locally. Certificates expire after one year; rerun `npm run cert` to
replace them. The certificate and private key in `certs/` are ignored by Git.

SQLite creates `data/vault.sqlite` and seeds
the demo automatically. Restarting preserves changes. Optionally copy `.env.example`
to `.env` to change `SERVER_ADDRESS`, `SERVER_PORT` (HTTP redirect), `HTTPS_PORT`, or `DB_PATH`.
`npm run keygen` writes a random `DOCUMENT_MASTER_KEY` into the ignored `.env` file
and keeps an existing key. It must be configured before opening encrypted storage.

```sh
npm test
```

Tests start real HTTP servers with isolated databases. They cover the API contract,
legitimate access, validation, persistence, and both attack regressions. On the
vulnerable snapshot, its tests deliberately assert successful attacks instead.

Docker is optional:

```sh
npm run cert
npm run keygen
docker compose up --build -d --wait
docker compose down
```

Docker mounts the local `certs/` directory read-only and stores data in its own
`vault-data` volume. `API_PORT` changes its HTTP host port; `HTTPS_PORT` changes its
HTTPS port (default `8443`).
If Docker Desktop cannot read `certs/` on a Windows network share, use a local
checkout for Docker so the certificate bind mount is available to the container.
To repeat an experiment from fresh fixtures, stop the app and delete
`data/vault.sqlite`; for Docker, use `docker compose down -v`. Both erase demo grants.
Reset before comparing snapshots so a previous grant does not authorize the attacker.

## Accounts and documents

Each password is `<username>-demo`. Sign in with the password, scan the enrollment QR
code in an authenticator app, and enter its six-digit TOTP code. Subsequent sign-ins
only require the password and TOTP code. A password alone creates a pending session
that cannot access document or permission endpoints. Sessions expire after 12 hours
and are cleared on server restart; TOTP enrollment persists in SQLite.

| ID | Username | Organization | Role |
| --- | --- | --- | --- |
| 1 | alice | A (1) | EMPLOYEE |
| 2 | bob | A (1) | WORKSPACE_MANAGER |
| 3 | adminA | A (1) | ORGANIZATION_ADMIN |
| 4 | charlie | B (2) | EMPLOYEE |
| 5 | diana | B (2) | WORKSPACE_MANAGER |

| Document | Filename | Organization | Owner | Initial MANAGE grants |
| --- | --- | --- | --- | --- |
| 1 | alice-notes.txt | A | alice | alice, bob |
| 2 | bob-confidential.txt | A | bob | bob |
| 3 | charlie-confidential.txt | B | charlie | charlie, diana |
| 4 | diana-project.txt | B | diana | diana |

Within the same organization, owners and workspace managers can read and manage;
explicit READ/WRITE/MANAGE permits reading, and MANAGE permits permission changes.
Organization administrators have no automatic document access. There is no document
content editing endpoint. Alice initially has access only to document 1.

## API

The document routes, fixture text, timestamps, and successful document JSON fields
match the original Java application. Authentication now uses the TOTP flow above.
Permission row IDs identify grants, not users.

| Method | Route | Response |
| --- | --- | --- |
| GET | `/api/health` | Public `200`, `{"status":"UP"}` |
| POST | `/api/auth/login` | `{"username":"alice","password":"alice-demo"}` returns a pending bearer token |
| POST | `/api/auth/enroll` | Pending bearer token returns a QR data URL and manual secret |
| POST | `/api/auth/verify` | Pending bearer token and `{"code":"123456"}` return an authenticated bearer token |
| POST | `/api/auth/logout` | Revokes the bearer token |
| GET | `/api/documents` | Authorized document summaries, sorted by ID |
| GET | `/api/documents/search?filename=alice` | Filename substring search returning document summaries |
| GET | `/api/documents/{id}` | Document summary plus `content` |
| GET | `/api/documents/{id}/permissions` | Grants sorted by user ID; requires management |
| PUT | `/api/documents/{id}/permissions` | Creates or updates one grant; returns it with `200` |

Alice's document list on fresh data:

```json
[{"id":1,"organizationId":1,"ownerId":1,"filename":"alice-notes.txt","createdAt":"2026-01-01T12:00:00Z"}]
```

A full document also has `content`, for example `"Alice's private notes from Organization A."`.
A permission response has `id`, `documentId`, `userId`, and `permission`.
PUT accepts `{"userId":1,"permission":"MANAGE"}`; allowed values are READ, WRITE, MANAGE.

Send `Authorization: Bearer <token>` on protected requests. Missing/invalid tokens
return `401`; pending tokens return `403`. Invalid JSON, IDs,
or permission values return `400`; non-JSON PUT returns `415`. Foreign recipients
return `400`, missing recipients `404`, and unauthorized management `403`.
Document GET returns `404` for unknown or unauthorized IDs. Permission GET/PUT
returns `403` for unknown or unauthorized documents; on `Vulnerable-Vault`, unknown
documents return `404`. Errors use `application/problem+json` with
`type`, `title`, `status`, `detail`, and `instance`; SQL and stack traces stay out of responses.

## The two experiments

Use the browser UI to authenticate, then pass its authenticated bearer token in
`Authorization` when repeating these examples with `curl.exe` in Windows PowerShell.
The `-k` flag accepts the self-signed development certificate for these requests.

MC1: change the document ID while authenticated as Alice:

```sh
curl -k -i -H "Authorization: Bearer <token>" https://127.0.0.1:8443/api/documents/1
curl -k -i -H "Authorization: Bearer <token>" https://127.0.0.1:8443/api/documents/3
```

On `Vulnerable-Vault`, both return `200`: the second leaks Charlie's confidential
Organization B document, and document 2 is also exposed. This revision returns
`200` then `404`. The fix calls the existing `DocumentAuthorization.canRead`
inside `DocumentService.get` before returning any content.

MC2: grant Alice management rights on Bob's document:

```sh
curl -k -i -H "Authorization: Bearer <token>" https://127.0.0.1:8443/api/documents/2/permissions
curl -k -i -X PUT -H "Authorization: Bearer <token>" -H "Content-Type: application/json" --data-binary '@examples/grant-alice-manage.json' https://127.0.0.1:8443/api/documents/2/permissions
curl -k -i -H "Authorization: Bearer <token>" https://127.0.0.1:8443/api/documents/2/permissions
```

On `Vulnerable-Vault`, the statuses are `403`, `200`, `200`. The grant persists and
Alice's document list includes document 2. On `main` and `Secured-Vault`, all three
return `403`; no grant is written. The fix calls the existing
`DocumentAuthorization.requireManagement` before looking up the recipient or
saving the grant. Permission reads use the same guard for missing documents too.

Authentication, document listing, and permission reading stay protected. SQL uses
bound parameters throughout; SQL injection is not one of these two experiments.

## Code and snapshots

`src/app.js` handles HTTP and input validation. `src/authentication.js` resolves
identity. `src/services/` holds the document and permission rules, with one shared
authorization class. `src/repository.js` owns SQL; `src/database.js` creates and seeds
SQLite. Services receive their dependencies through constructors.

## Document storage proof

The same command shows plaintext on the baseline and ciphertext on the encrypted
snapshot. No server, certificate, or sign-in is needed:

```sh
git switch encryption-before-Vault
node --env-file-if-exists=.env scripts/prove-document-storage.js
git switch encryption-Vault
node scripts/generate-master-key.js
node --env-file-if-exists=.env scripts/prove-document-storage.js
```

This creates a temporary SQLite file, closes it, and reads its stored rows directly
without the API. Each run starts fresh, so data from a previous branch cannot affect
the result. The temporary file is removed afterward; your application database is untouched.
`npm run proof:documents` is an alias; the direct Node commands also work from
Windows network paths.

Observed before:

```json
{"id":1,"content":"Alice's private notes from Organization A."}
```

Observed after (ciphertext, IVs, tags, and wrapped keys change on each fresh run):

```json
{"id":1,"version":1,"content":"ViSMamv0oSNm8qWwrATZjKegl621jk6/QFsTKpeANSRJugfiPWma20Mn","iv":"khH67kLCme8a1rAG","authTag":"n9f6SNS/mjIgkSkV6DIf6g=="}
```

The encrypted proof also prints the wrapped key row from `document_keys`. It never
prints the master key or an unwrapped document key.

For **any older JavaScript snapshot**, which may not have the npm proof script,
this identical command also shows its raw SQLite contents in a fresh in-memory database:

```sh
node --env-file-if-exists=.env --input-type=module -e "import { openDatabase } from './src/database.js'; const db = openDatabase(':memory:'); console.log(db.prepare('SELECT id, content FROM documents ORDER BY id').all()); db.close();"
```

To inspect the actual local application file after starting the app:

```sh
node --env-file-if-exists=.env --input-type=module -e "import { DatabaseSync } from 'node:sqlite'; const db = new DatabaseSync(process.env.DB_PATH ?? 'data/vault.sqlite', {readOnly:true}); console.log(db.prepare('SELECT id, content FROM documents ORDER BY id').all()); db.close();"
```

## Envelope encryption

`src/document-encryption.js` uses Node's built-in
[AES-256-GCM APIs](https://nodejs.org/docs/latest-v24.x/api/crypto.html#class-cipheriv).
Every content version gets a new random 32-byte data key. Encrypting the content
and wrapping its key each use an independent random 12-byte IV and a 16-byte
authentication tag. Document ID, organization ID, version, and purpose are
authenticated too, so copying envelopes between rows fails verification.

`documents.content` holds Base64 ciphertext; `version`, `iv`, and `authTag` describe
that ciphertext. The separate `document_keys` table holds the data key encrypted
under `DOCUMENT_MASTER_KEY`, with its own IV/tag. The master key is 32 random bytes
encoded as 64 hexadecimal characters and stays outside SQLite in the environment.
Unwrapped data keys exist only in memory during encryption/decryption.

Authorized API/UI reads still show readable content. Document access is checked
before decryption, and lists expose only the original metadata fields. Missing or
invalid master configuration stops startup; wrong keys or damaged records fail
authentication without falling back to plaintext.

Opening an older database migrates its existing content transactionally and keeps
IDs, metadata, permissions, passwords, and TOTP enrollment. The migration scrubs
replaced cells and compacts SQLite so old content is absent from the resulting
database file. Existing external backups remain separate copies. Keep the master
key with your backup: generating another key cannot recover existing documents.

The MVP stores only the current version. `VaultRepository.saveDocumentVersion`
increments its version and atomically replaces the ciphertext and wrapped key;
tests exercise version 1 and version 2. There is no new editing UI or API.

`npm test` checks fresh keys/IVs, tampering, wrong keys, version changes, migration
rollback, persistence, removal of plaintext from the database file, and the existing
authorization/TOTP/API behavior. `main` and `encryption-Vault` contain the finished
encryption change; previous snapshots retain their original behavior.

## Filename search experiment

`sql-injection-before-Vault` deliberately inserts the filename into SQL. Sign in
as Alice through the existing TOTP flow and use her authenticated bearer token.
Import `examples/search.postman_collection.json` into Postman, set `baseUrl` and
`token`, then send both requests:

| Filename | Vulnerable result | Secured result |
| --- | --- | --- |
| `alice` | `200`, document 1 | `200`, document 1 |
| `' OR 1=1 --` | `200`, documents 1, 2, 3, 4, including Organization B | `200`, `[]` |

The ordinary query checks organization and document access. The injected `OR 1=1`
changes that condition and comments out the rest of the query. Search returns
metadata only. `node --test test/search.test.js` reproduces the experiment.

`main` and `sql-injection-Vault` fix the query in place: `filename LIKE ?` binds
the pattern with `.all(..., \`%${filename}%\`)`. The tenant and document permission
conditions stay in the same query. Apostrophes, empty searches, and LIKE wildcards
continue to work.

Start the vulnerable snapshot:

```sh
git switch sql-injection-before-Vault
npm start
```

In Postman, send `GET https://127.0.0.1:8443/api/documents/search` with Alice's
verified bearer token. In Params, set `filename` to `alice`, then to `' OR 1=1 --`.
Stop the server, switch snapshots, restart, and sign in again before repeating:

```sh
git switch sql-injection-Vault
npm start
```

For automated Postman assertions, import the collection from the current snapshot;
its expected injection IDs change from `[1,2,3,4]` to `[]`. Set `baseUrl` and `token`.
The same requests can be run using the
[Postman CLI](https://learning.postman.com/docs/postman-cli/postman-cli-collections):

```sh
postman collection run examples/search.postman_collection.json --env-var "token=<Alice's verified token>" --ssl-extra-ca-certs certs/localhost.pem
```

Both Postman runs passed their two assertions. All 39 Node tests pass, including
normal search, injection variants, tenant isolation, and explicit permissions.

Verification: all 34 tests pass. The raw SQLite proof was run before and after;
the Docker image was also checked with HTTPS/TOTP, authorized decryption, stored
ciphertext, and wrapped keys. The network-share certificate mount required copying
the development certificates into the isolated test container.

`Vulnerable-Vault` preserves the vulnerable baseline. Two subsequent commits fixed
each missing check in place; `Secured-Vault` preserves that version. The current
`main` adds TOTP authentication, Argon2id, HTTPS, the browser UI, and document
envelope encryption on top of those fixes.
