# Vault

A small Node.js document API for a school security project. This revision fixes
MC1; MC2 remains deliberately vulnerable. Use fictional data and run it locally.

The API uses [Express](https://expressjs.com/en/5x/api/), Node's built-in
[SQLite](https://nodejs.org/docs/latest-v24.x/api/sqlite.html), scrypt password hashing,
and the built-in test runner. Express is the only package dependency.

## Run

Install Node.js 24 or newer, then:

```sh
npm ci
npm start
```

The API listens at `http://127.0.0.1:8080`. SQLite creates `data/vault.sqlite` and seeds
the demo automatically. Restarting preserves changes. Optionally copy `.env.example`
to `.env` to change `SERVER_ADDRESS`, `SERVER_PORT`, or `DB_PATH`.

```sh
npm test
```

Tests start real HTTP servers with isolated databases. They cover the API contract,
legitimate access, validation, persistence, the MC1 fix, and the successful MC2 attack.

Docker is optional:

```sh
docker compose up --build -d --wait
docker compose down
```

Docker stores data in its own `vault-data` volume. `API_PORT` changes its host port.
To repeat an experiment from fresh fixtures, stop the app and delete
`data/vault.sqlite`; for Docker, use `docker compose down -v`. Both erase demo grants.
Reset before comparing snapshots so a previous grant does not authorize the attacker.

## Accounts and documents

All protected endpoints use HTTP Basic. Each password is `<username>-demo`.

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

The routes, credentials, fixture text, timestamps, and successful JSON fields match
the original Java application. Permission row IDs identify grants, not users.

| Method | Route | Response |
| --- | --- | --- |
| GET | `/api/health` | Public `200`, `{"status":"UP"}` |
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

Missing/invalid credentials return `401` with a Basic challenge. Invalid JSON, IDs,
or permission values return `400`; non-JSON PUT returns `415`. Foreign recipients
return `400`, missing recipients `404`, and unauthorized management `403`.
Unknown documents return `404`. Errors use `application/problem+json` with
`type`, `title`, `status`, `detail`, and `instance`; SQL and stack traces stay out of responses.

## The two experiments

Use `curl.exe` in Windows PowerShell. Run these from the repository root.

MC1: change the document ID while authenticated as Alice:

```sh
curl -i -u alice:alice-demo http://127.0.0.1:8080/api/documents/1
curl -i -u alice:alice-demo http://127.0.0.1:8080/api/documents/3
```

On `Vulnerable-Vault`, both return `200`: the second leaks Charlie's confidential
Organization B document, and document 2 is also exposed. This revision returns
`200` then `404`. The fix calls the existing `DocumentAuthorization.canRead`
inside `DocumentService.get` before returning any content.

MC2: grant Alice management rights on Bob's document:

```sh
curl -i -u alice:alice-demo http://127.0.0.1:8080/api/documents/2/permissions
curl -i -u alice:alice-demo -X PUT -H "Content-Type: application/json" --data-binary '@examples/grant-alice-manage.json' http://127.0.0.1:8080/api/documents/2/permissions
curl -i -u alice:alice-demo http://127.0.0.1:8080/api/documents/2/permissions
```

The statuses are `403`, `200`, `200`. The grant persists and Alice's document list
now includes document 2. `PermissionService.update` checks both organization
boundaries but omits `DocumentAuthorization.requireManagement`.

Authentication, document listing, and permission reading stay protected. SQL uses
bound parameters throughout; SQL injection is not one of these two experiments.

## Code and snapshots

`src/app.js` handles HTTP and input validation. `src/authentication.js` resolves
identity. `src/services/` holds the document and permission rules, with one shared
authorization class. `src/repository.js` owns SQL; `src/database.js` creates and seeds
SQLite. Services receive their dependencies through constructors.

`Vulnerable-Vault` preserves this baseline. Subsequent commits on `main` fix each
missing check in place; `Secured-Vault` preserves the final version. Both use the
same dependencies, schema, routes, and services. No branch-dependent runtime flag
or alternate application is needed.
