# Vault

A small Node.js document API for a school security project. `main` and
`Secured-Vault` fix two authorization vulnerabilities; `Vulnerable-Vault` preserves
both attacks. Use fictional data and run it locally.

The API uses [Express](https://expressjs.com/en/5x/api/), Node's built-in
[SQLite](https://nodejs.org/docs/latest-v24.x/api/sqlite.html), scrypt password hashing,
and the built-in test runner. Express serves the API and small browser UI; `qrcode`
generates authenticator enrollment images.

## Run

Install Node.js 24 or newer, then:

```sh
npm ci
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

```sh
npm test
```

Tests start real HTTP servers with isolated databases. They cover the API contract,
legitimate access, validation, persistence, and both attack regressions. On the
vulnerable snapshot, its tests deliberately assert successful attacks instead.

Docker is optional:

```sh
npm run cert
docker compose up --build -d --wait
docker compose down
```

Docker mounts the local `certs/` directory read-only and stores data in its own
`vault-data` volume. `API_PORT` changes its HTTP host port; `HTTPS_PORT` changes its
HTTPS port (default `8443`).
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

```sh
npm run proof:documents
```

This creates a temporary SQLite file, closes it, and reads its stored rows directly
without the API. On `encryption-before-Vault`, `content` contains readable document
text. The temporary file is removed afterward; your application database is untouched.

`Vulnerable-Vault` preserves the vulnerable baseline. Two subsequent commits fixed
each missing check in place; `Secured-Vault` preserves that version. The current
`main` adds TOTP authentication and the browser UI on top of those fixes.
