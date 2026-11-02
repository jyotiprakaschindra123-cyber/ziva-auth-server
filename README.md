# Ziva Browse authentication server

A small Node.js/Express implementation of the authentication contract recovered
from Ziva Browse 2.2.1.0. It implements the client-visible login, device proof,
session, heartbeat, logout and admin APIs.

The original server's private implementation was not available. This server
matches the recovered client contract (paths, headers, field names, states and
user-facing messages) and defines the exact canonical signature format used by
the companion Windows client in this repository.

## Stack

- Node.js 20+
- Express
- PostgreSQL for persistent storage
- In-memory storage when `DATABASE_URL` is unset (local development only)

## Local development

```powershell
cd server
npm install
$env:ADMIN_TOKEN = "dev-admin-token"
$env:ZIVA_TOKEN_PEPPER = "dev-pepper"
npm run dev
```

The server listens on `http://127.0.0.1:3000` and uses memory storage. Create a
user through the admin API:

```powershell
$body = @{ username = "alice"; password = "secret123"; lock = "123" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:3000/api/admin/users `
  -Headers @{ Authorization = "Bearer dev-admin-token" } `
  -ContentType "application/json" -Body $body
```

Then point the client at it. Either set `ZIVA_AUTH_BASE_URL`, or put one line in
`auth.txt` beside `msedge.exe`:

```text
http://127.0.0.1:3000
```

The Windows client sends the lock as a number: `123` for a lock, `-1` when the
field is empty. The server normalizes `-1`/empty to “no lock” and pads numeric
locks to three digits (`12` → `012`). The admin API and CLI accept three-digit
strings.

Run the server tests with:

```powershell
npm test
```

## Admin website

Open `http://127.0.0.1:3000/` (or `/admin`) in a browser. The page asks for the
`ADMIN_TOKEN`; the key stays in `sessionStorage` and is sent as a Bearer token.
From the dashboard you can:

- create a customer ID (username, password, optional three-digit lock) and copy
  the credentials once;
- search and export the account list, with device and session counts;
- inspect a customer's bound devices and sessions, then revoke a device or a
  single session;
- reset a password and lock, or disable/enable an account;
- read the recent audit trail.

The dashboard is one static file, `src/admin.html`, served by Express.
`vercel.json` includes it in the serverless bundle with `includeFiles`; keep that
setting if you move or rename the file.

Programmatic clients can still use the JSON API below. `GET /` returns JSON when
the request prefers JSON (`Accept: application/json`) or when `?format=json` is
appended; `GET /api` always returns the service descriptor.

## Postgres

Set `DATABASE_URL` to a Postgres connection string. The schema is created on the
first request (`src/schema.js`); `db/schema.sql` is the same schema for manual
provisioning.

Create a user from the CLI:

```powershell
$env:DATABASE_URL = "postgres://..."
node scripts/create-user.js alice secret123 123
```

## Vercel deployment

This folder is standalone-deployable. When deploying from the main clone (where
the Qt client is at the repository root), set **Root Directory** to `server`.
When deploying this folder as its own repository, leave Root Directory empty.

1. Push this repository to GitHub/GitLab.
2. Import the project in Vercel.
3. Set **Root Directory** as described above. Framework preset **Other**, install
   command `npm install`, build command empty, output directory empty.
4. Add a Postgres database (Vercel Postgres, Neon, or any Postgres 14+) and set
   `DATABASE_URL`. Prefer the pooled connection string. The schema is created on
   the first request, so no migration step is required.
5. Add environment variables for Production and Preview:
   - `DATABASE_URL` — Postgres connection string
   - `ZIVA_TOKEN_PEPPER` — long random string (32+ bytes)
   - `ADMIN_TOKEN` — long random admin bearer token
   - optional: `ZIVA_SESSION_TTL_SECONDS`, `ZIVA_HEARTBEAT_SECONDS`,
     `ZIVA_MAX_DEVICES`, `ZIVA_MAX_LOGIN_FAILURES`
6. Deploy. The admin dashboard is served at `/`, the API under `/api/*`, and
   `https://<deployment>/api/health` should return `"storage":"postgres"` and
   `"admin_enabled":true`.
7. Open the deployment root and paste `ADMIN_TOKEN` to create the first account
   in the browser (see below).
8. Point the Windows client at the deployment with `ZIVA_AUTH_BASE_URL` or an
   `auth.txt` beside `msedge.exe` containing the deployment URL.

The included `vercel.json` routes all requests to `api/index.js` and bundles
`src/admin.html` through `includeFiles`. You can also deploy the folder directly:

```powershell
cd server
vercel --prod
```

### First account

The quickest route is the dashboard at `https://<deployment>/`; paste
`ADMIN_TOKEN`, fill in the company/customer username, password and optional lock,
then copy the generated credentials from the confirmation dialog. The same
operation through the API is:

```powershell
$body = @{ username = "alice"; password = "secret123"; lock = "123" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri https://<deployment>/api/admin/users `
  -Headers @{ Authorization = "Bearer $env:ADMIN_TOKEN" } `
  -ContentType "application/json" -Body $body
```

Omit `lock` for an account without a lock. Never put the admin token in the
client or in `auth.txt`.

## API

### Public

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/`, `/admin` | Admin dashboard (HTML) or service JSON |
| `GET` | `/api` | Service descriptor JSON |
| `GET` | `/api/health` | Health and storage mode |
| `POST` | `/api/authenticate` | Login + device registration |
| `POST` | `/api/auth/session/heartbeat` | Extend and validate a session |
| `POST` | `/api/auth/session/logout` | Revoke a session |

### Admin (Bearer `ADMIN_TOKEN`)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/admin/users` | Create user |
| `GET` | `/api/admin/users` | List users + counts |
| `POST` | `/api/admin/users/:username/disable` | Disable/enable user |
| `POST` | `/api/admin/users/:username/password` | Reset password/lock |
| `GET` | `/api/admin/users/:username/devices` | List devices bound to a user |
| `POST` | `/api/admin/devices/:deviceId/revoke` | Revoke device |
| `POST` | `/api/admin/sessions/:sessionId/revoke` | Revoke session |
| `GET` | `/api/admin/sessions?username=alice` | List user sessions |
| `GET` | `/api/admin/audit?limit=100` | Recent audit events |

## Device proof format

The client sends these headers on every protected request:

- `x-ziva-protocol-version: 2`
- `x-ziva-client-version: 2.2.1`
- `x-ziva-proof-version: ziva-device-proof-v1`
- `x-ziva-device-signature`
- `x-ziva-device-key`
- `x-ziva-installation-id`

The signature is RSA-SHA256 (PKCS#1 v1.5), base64url without padding, over one of
these UTF-8 strings (fields separated by `\n`, no trailing newline):

**Login**

```text
ziva-device-proof-v1
login
<installation_id>
<username>
<request_nonce>
<request_timestamp>
<device_key_base64url>
```

**Session (heartbeat/logout)**

```text
ziva-device-proof-v1
session
<installation_id>
<session_id>
<request_nonce>
<request_timestamp>
<device_key_base64url>
```

`request_timestamp` is Unix seconds. The server allows ±300 seconds by default
and rejects reused `(installation_id, nonce)` pairs.

The public key is an RSA SPKI DER structure encoded as base64url. On the first
successful login the server binds the installation ID to that key
(trust-on-first-use). Later logins and heartbeats must use the same key.

## Security notes

- Set a strong `ZIVA_TOKEN_PEPPER` and `ADMIN_TOKEN` in production.
- Passwords are hashed with scrypt (N=16384, r=8, p=1, 64-byte key).
- Session tokens are random 32-byte values; only their SHA-256 hash plus pepper
  is stored.
- Use HTTPS. Vercel provides TLS automatically.
- The memory store is for development only; data disappears on restart.
- The admin API is disabled when `ADMIN_TOKEN` is empty.
- The client stores its installation identity with Windows DPAPI and keeps its
  RSA key in the Microsoft Software Key Storage Provider.
