# Secure Notes App

A small, security-focused Node.js web app for creating, updating, listing, and deleting notes.

## Security controls included

- Basic Authentication for all app/API routes except `/health`
- Strict input validation using `zod`
- SQLite access via `sql.js` with parameterized queries to prevent SQL injection
- Security headers via `helmet` (including CSP)
- Request rate limiting
- Request payload size limits
- HTTP parameter pollution protection (`hpp`)
- `X-Powered-By` disabled
- Constant-time credential comparison
- Same-origin enforcement for state-changing requests (CSRF mitigation)
- Optional HTTPS enforcement (`REQUIRE_HTTPS=true`)
- Safe frontend rendering (`textContent`, not `innerHTML`)

## Setup

1. Install Node.js 20+.
2. Install dependencies:

```bash
npm install
```

3. Copy `.env.example` to `.env` and set secure credentials.

4. Run:

```bash
npm start
```

5. Open `http://localhost:3000`.

## Environment variables

- `NODE_ENV`: `development` or `production`
- `PORT`: server port (default: `3000`)
- `PUBLIC_ORIGIN`: canonical app origin, e.g. `https://notes.example.com`
- `TRUST_PROXY`: number of reverse proxies to trust (default: `0`)
- `REQUIRE_HTTPS`: enforce HTTPS (`true`/`false`)
- `BASIC_AUTH_USER`: Basic Auth username
- `BASIC_AUTH_PASS`: Basic Auth password
- `RATE_LIMIT_WINDOW_MS`: rate-limit window in milliseconds
- `RATE_LIMIT_MAX`: max requests per window per IP
- `MAX_BODY_KB`: max JSON body size in KB
- `DB_PATH`: SQLite file path

## Production notes

- Always run behind HTTPS and set `REQUIRE_HTTPS=true`.
- Set `PUBLIC_ORIGIN` to your real external origin (required in production).
- Set `TRUST_PROXY` to your exact reverse-proxy hop count (for example, `1` behind one proxy).
- Set strong, unique `BASIC_AUTH_USER` and `BASIC_AUTH_PASS`.
- Put the app behind a hardened reverse proxy (Nginx/Caddy/Cloudflare).
- Keep dependencies patched (`npm audit` and regular updates).
- Add centralized logging/monitoring and backups for `DB_PATH`.

## Important

No software can be guaranteed "100% safe." This app applies strong baseline controls, but you must still do ongoing patching, monitoring, infrastructure hardening, and security testing before/after deployment.
