# Secure Notes App

Production-hardened Node.js notes API with session-based auth, CSRF protection, rate limiting, and SQLite persistence.

## Setup
- Requirements: Node.js 18.18+.
- Copy `.env.example` to `.env` and set `SESSION_SECRET` (strong, random). Optionally set `ADMIN_PASSWORD` to auto-provision an admin user.
- Install dependencies: `npm install`.
- Start (dev): `npm run dev` (defaults to port 3000).
- Start (prod): `npm start` (sets `NODE_ENV=production`; ensure HTTPS + `TRUST_PROXY=1` when behind a proxy).

## Security Defaults
- Helmet with strict CSP, HSTS (via HTTPS), no `X-Powered-By`.
- HTTP-only, same-site `strict` cookies; `secure` enabled in production or when `SECURE_COOKIES=1`.
- Session fixation protection (session regeneration on login/register) with persistent SQLite-backed session store (MemoryStore only in tests).
- CSRF protection on all mutating routes; fetch token via `GET /csrf-token` and send header `x-csrf-token`.
- Input validation via Joi; strong password policy (min 12 chars with upper/lower/number/symbol).
- Rate limiting on all routes plus tighter limits on auth.
- HPP mitigation, JSON/body size limits, and parameterized SQL queries.
- Strict CSP-compatible UI (`/public/index.html` + `/public/app.js`) that uses `fetch` with credentials and encodes user content safely.

## API (JSON)
All responses are JSON. Use cookies for session auth.

- `GET /healthz` → `{ status: "ok" }`
- `GET /csrf-token` → `{ csrfToken }` (must be called with session cookie)

Auth
- `POST /auth/register` (if `ALLOW_REGISTRATION` not `0`) body: `{ username, password }` + `x-csrf-token`
- `POST /auth/login` body: `{ username, password }` + `x-csrf-token`
- `POST /auth/logout` + `x-csrf-token`
- `GET /auth/me`

Notes (auth required)
- `GET /notes`
- `POST /notes` body: `{ title, content }` + `x-csrf-token`
- `PUT /notes/:id` body: `{ title, content }` + `x-csrf-token`
- `DELETE /notes/:id` + `x-csrf-token`

## Testing
- Runs with in-memory SQLite and MemoryStore sessions: `npm test`

## Operational Guidance
- Always run behind HTTPS with `SECURE_COOKIES=1` (or set `NODE_ENV=production` which enables it).
- Set `TRUST_PROXY=1` when behind a reverse proxy so secure cookies and rate limits use the correct client IP.
- Back up `data/notes.db` (and `data/sessions.db` if you care about active sessions); `.gitignore` excludes these.
- If public signups are not desired, set `ALLOW_REGISTRATION=0`; deploy with a pre-provisioned admin via `ADMIN_PASSWORD`.
