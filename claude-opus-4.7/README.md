# Secure Notes

A small server-rendered Node.js / Express notes app (signup, login, per-user CRUD) with security as a first-class concern. Designed to be deployed behind a TLS-terminating reverse proxy.

## Quickstart

```bash
node --version            # must be >= 20
npm install
cp .env.example .env
# Generate a strong secret:
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
# paste it as SESSION_SECRET in .env
npm start
```

Then open <http://127.0.0.1:3000>.

## Required environment

See [`.env.example`](./.env.example). The app refuses to start without a `SESSION_SECRET` of at least 64 characters.

## Deploying to production

This app must run **behind a reverse proxy that terminates TLS** (nginx, Caddy, AWS ALB, Cloudflare, etc.). It does not handle TLS itself.

1. Set `NODE_ENV=production` so:
   - HSTS is enabled
   - Session and CSRF cookies are flagged `Secure`
   - `upgrade-insecure-requests` is added to the Content-Security-Policy
   - Stack traces are not rendered to users
2. If the proxy is on a different host than the app, set `TRUST_PROXY=true`. The app will trust **one** proxy hop. Do not enable this in topologies where untrusted clients can set `X-Forwarded-*` headers — it would let them spoof source IPs and bypass rate limits.
3. Bind the app to localhost (`HOST=127.0.0.1`) when the proxy is on the same host; expose only the proxy.
4. Ensure the data directory is writable by the app user only (`chmod 700`) and **not** served by the proxy.
5. Run as a non-root user under a process supervisor (systemd, PM2, k8s, etc.).
6. Back up `./data/app.sqlite`. Treat it as containing PII (it stores password hashes).

## Security controls

| Threat | Control |
| --- | --- |
| SQL injection | All queries are prepared statements with bound parameters via `better-sqlite3`. No user input ever flows into SQL strings. |
| XSS (stored / reflected) | EJS templates auto-escape with `<%= %>`. No `<%- %>` is used on user-controlled values. A strict CSP (`default-src 'self'`, no `unsafe-inline`) blocks inline and remote scripts/styles. `X-Content-Type-Options: nosniff` is set. |
| Clickjacking | `frame-ancestors 'none'` (CSP) and `X-Frame-Options: DENY`. |
| CSRF | Session cookie is `SameSite=Strict` + `HttpOnly`. Every state-changing request additionally requires a per-session synchronizer token (`_csrf` field), checked with `crypto.timingSafeEqual`. Token rotates after login/signup. |
| Session hijacking | Cookie is `HttpOnly`, `Secure` in production, `SameSite=Strict`, signed with a high-entropy secret. Sessions are server-side (SQLite store); the cookie holds only a session id. Sessions regenerate on login (prevents fixation) and are destroyed on logout. |
| Brute-force login | `bcrypt` cost 12, with a constant-time dummy hash compare for unknown users to avoid user enumeration via timing. Per-IP rate limit of 10 attempts / 15 min on `/login` (failures only). Generic "Invalid username or password" error for all failure modes. |
| Account enumeration | Login errors are identical for "no such user" and "wrong password". Signup returns a distinct "username taken" error by design (alternative is silent ambiguous behavior, which harms UX) — rate limited to 5 signups / hour / IP. |
| Weak passwords | Minimum 12 characters enforced server- and client-side. No max truncation surprises (capped at 128). Passwords are never logged. |
| Mass assignment / oversized payloads | `express.urlencoded({ limit: 16KB })`. Schemas validate exact field shapes via `zod`; unknown fields are dropped. |
| Authorization bugs | Every notes query binds `user_id = ?` so even an authorization mistake upstream cannot read or modify another user's row. Session-bound user is re-fetched from the DB each request (so deleted accounts cannot keep using their session). |
| Denial of service | Global per-IP rate limit (300 req/min). Body size limits. Strict input length limits. Stack-trace responses suppressed. |
| Open redirect | The app contains no user-controlled redirect targets. |
| Header injection / referrer leaks | `Referrer-Policy: same-origin`. `noSniff`, COOP/CORP same-origin. HSTS in production. |
| Static file traversal | Only `public/styles.css` is served at `/static`. `dotfiles: ignore`, `index: false`. No user-uploaded files. |
| Secret leakage | `.env` is gitignored; `.env.example` ships placeholders only. Errors are logged server-side; clients receive a generic message in production. |
| Process crashes | Uncaught exceptions trigger graceful shutdown so the supervisor can restart with a clean state. |

## Threat model & known limitations

- **Single-instance deployment assumed.** The rate limiter and session store are local to one process. To scale horizontally, swap to Redis (`rate-limit-redis`, `connect-redis`) so limits and sessions are shared.
- **No password reset flow.** Adding one introduces account-takeover surface (email enumeration, token replay, SMTP integration). Out of scope here; if added, follow OWASP ASVS 6.x.
- **No 2FA.** Recommended for any real-world deployment with sensitive notes.
- **No CSP `report-uri`.** Add one in production to catch policy violations.
- **No structured audit log.** Console logs are sufficient for development; production should ship to a managed log sink and add per-user audit events for login, password change, and note deletes.
- **Backups.** SQLite is a single file — use `sqlite3 .backup` or stream-level snapshots to avoid a partial-file copy under load.

## Project layout

```
src/
  server.js              app wiring, helmet/CSP, sessions, listener
  config.js              env validation (zod), frozen config
  db.js                  schema + prepared statements
  validators.js          zod schemas for credentials, notes, ids
  middleware/
    auth.js              session -> user, requireAuth, requireGuest
    csrf.js              synchronizer-token CSRF
    rateLimit.js         global / login / signup limiters
    errorHandler.js      404 + sanitized error renderer
  routes/
    auth.js              /login /signup /logout
    notes.js             /notes CRUD (per-user)
  views/                 EJS templates (auto-escaping)
public/
  styles.css             only static asset served
```

## Development

`npm run dev` enables Node's `--watch` flag. Logs go to stdout/stderr; do not pipe to a world-readable file.
