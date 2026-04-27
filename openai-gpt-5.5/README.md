# Secure Notes

A small Node.js notes app with local user accounts and owner-scoped note CRUD.

No app can be honestly guaranteed "100% safe" in the real world. This scaffold is built to reduce common web risks by default: authentication is required, sessions are opaque and HttpOnly, unsafe requests require CSRF tokens, note access is scoped by user, SQL uses prepared statements, output is HTML-escaped, and responses include hardened security headers.

## Run Locally

```sh
npm install
npm run dev
```

Open `http://localhost:3000`.

## Production Setup

Copy `.env.example` into your deployment environment and set real values:

```sh
NODE_ENV=production
PORT=3000
APP_ORIGIN=https://notes.example.com
DATABASE_FILE=/var/lib/secure-notes/notes.sqlite
TRUST_PROXY=1
SESSION_COOKIE_SECURE=1
SESSION_DAYS=7
```

Run behind HTTPS. If TLS terminates at a reverse proxy, keep `TRUST_PROXY=1` so client IP handling is correct. Keep `SESSION_COOKIE_SECURE=1` in production; the app refuses to start if it is disabled.

## Security Controls

- Authentication with memory-hard `scrypt` password hashing.
- Session cookies are `HttpOnly`, `SameSite=Lax`, `Secure` in production, and use the `__Host-` prefix in production.
- Session tokens are stored hashed in SQLite, not as raw bearer tokens.
- CSRF tokens are required for login, registration, logout, create, update, and delete.
- Notes are always queried and mutated with `user_id`, preventing cross-user access.
- SQLite statements are parameterized.
- User content is escaped before rendering.
- Helmet sets a strict Content Security Policy, frame protection, MIME sniffing protection, and HSTS in production.
- Request bodies are size-limited.
- Login/register and global request rate limits are enabled.
- Production errors return generic messages.

## Verification

```sh
npm test
npm audit --omit=dev
```

Run dependency updates and security audits regularly. Review logs and backups as sensitive, because notes and password hashes are stored in the database.

## Operational Notes

- Back up the SQLite database and protect it with filesystem permissions.
- Do not expose the database file through the web server or container volume mounts.
- Add MFA, email verification, centralized audit logging, and managed database backups before using this for high-risk data.
- Put automated dependency scanning and container/image scanning in CI.
