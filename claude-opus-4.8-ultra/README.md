# Secure Notes

A small, **security-first** Node.js web app for creating, updating, and deleting
personal notes. Each account's notes are private to that account.

## Features

- Register / log in / log out (per-user accounts)
- Create, edit, and delete notes
- Server-rendered, no client-side JavaScript required

## Security controls

This app was built defensively. Key protections:

| Area | Control |
|------|---------|
| **SQL injection** | All queries use `better-sqlite3` prepared statements with bound parameters — no string concatenation. |
| **XSS** | EJS auto-escapes all output (`<%= %>`). A strict Content-Security-Policy (no inline/3rd-party scripts) provides defense-in-depth. |
| **CSRF** | Per-session synchronizer token embedded in every form, verified in constant time, plus `SameSite=Lax` cookies. |
| **Authentication** | Passwords hashed with **bcrypt** (cost 12). Login failures are generic; a timing decoy hides whether a username exists. |
| **Session security** | `httpOnly`, `Secure` (prod), `SameSite=Lax` cookies; session **regenerated on login** (fixation defense); persistent SQLite store. |
| **Authorization (IDOR)** | Every note query is scoped by `user_id` from the session — you cannot touch another user's notes even by guessing IDs. |
| **Brute force / DoS** | Rate limiting (global + stricter on auth) and small request-body limits. |
| **Transport** | HSTS and `upgrade-insecure-requests` in production; `Secure` cookies. |
| **HTTP headers** | `helmet` (CSP, X-Content-Type-Options, frameguard, referrer-policy, etc.). |
| **Secrets** | Loaded from environment; the app refuses to start without a strong `SESSION_SECRET`. |
| **Error handling** | Centralized; no stack traces or internals leak to clients in production. |

## Requirements

- Node.js **20+**
- A C/C++ toolchain is only needed if prebuilt binaries for `better-sqlite3` /
  `bcrypt` aren't available for your platform (usually they are).

## Setup

```bash
# 1. Install dependencies
npm install

# 2. Create your environment file
cp .env.example .env        # Windows PowerShell: Copy-Item .env.example .env

# 3. Generate a strong session secret and paste it into .env (SESSION_SECRET=)
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"

# 4. Run
npm start                   # production-style
npm run dev                 # auto-reload during development
```

Then open <http://127.0.0.1:3000>.

## Production deployment checklist

- [ ] Set `NODE_ENV=production`.
- [ ] Set a unique, high-entropy `SESSION_SECRET` (48+ random bytes).
- [ ] **Terminate TLS** in front of the app (reverse proxy / load balancer) and
      serve only over HTTPS — `Secure` cookies require it.
- [ ] Set `TRUST_PROXY=1` (or the real proxy count) when behind a proxy so
      secure-cookie detection and rate-limit IPs are correct.
- [ ] Put the app behind a process manager (systemd, pm2) with auto-restart.
- [ ] Back up the SQLite database file (`DATABASE_PATH`) regularly.
- [ ] Keep dependencies patched: run `npm audit` and update routinely.
- [ ] Ship server logs to a central, access-controlled location.

## Project layout

```
src/
  server.js              app wiring + security middleware
  config.js              validated env configuration
  db.js                  SQLite connection + schema
  validators.js          zod input schemas
  middleware/security.js auth guard + CSRF
  models/                userModel, noteModel (prepared statements)
  routes/                auth, notes
  views/                 EJS templates (auto-escaped)
public/styles.css        external stylesheet (CSP-friendly)
```

## Notes on scope

This is intentionally small and dependency-light. For larger deployments you may
want: account email verification + password reset, 2FA, audit logging, a managed
database, and automated dependency scanning in CI.
