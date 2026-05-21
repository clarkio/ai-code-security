# Secure Notes

A production-oriented Node.js notes application with defense-in-depth security controls.

## Features

- User registration and session-based authentication
- Create, read, update, and delete notes (per-user isolation)
- Server-rendered UI with auto-escaping templates
- SQLite storage with parameterized queries and foreign keys

## Security controls

| Threat | Mitigation |
|--------|------------|
| SQL injection | Parameterized statements only (`better-sqlite3`) |
| XSS | EJS `<%= %>` escaping; strict Content-Security-Policy |
| CSRF | Double-submit cookie pattern (`csrf-csrf`) on all state-changing requests |
| Session fixation | Session regeneration on successful login |
| Session hijacking | `httpOnly`, `secure` (production), `sameSite=strict` cookies |
| IDOR | All note queries scoped by `user_id` from session |
| Brute force | Rate limits on auth (10/15min) and writes (30/min) |
| Mass assignment | Explicit Zod schemas; no direct `req.body` passthrough |
| Password storage | bcrypt (12 rounds) |
| HTTP hardening | Helmet (CSP, HSTS in production), HPP, disabled `X-Powered-By` |
| Information disclosure | Generic error messages; no stack traces to users |

## Quick start

```bash
cp .env.example .env
# Edit .env — set SESSION_SECRET (min 32 chars):
# openssl rand -base64 48

npm install
npm run db:init
npm start
```

Open http://127.0.0.1:3000

## Production deployment

1. Set `NODE_ENV=production`
2. Generate a strong `SESSION_SECRET` (48+ random bytes)
3. Terminate TLS at a reverse proxy (nginx, Caddy, cloud load balancer)
4. Set `TRUST_PROXY=true` so secure cookies and rate limits work correctly
5. Bind to localhost (`HOST=127.0.0.1`) and expose only via the proxy
6. Run as a non-root user; restrict filesystem permissions on `data/`
7. Keep dependencies updated: `npm audit` and patch regularly
8. Back up `data/notes.db` on a schedule

### Example reverse proxy requirements

- HTTPS only (redirect HTTP → HTTPS)
- Forward `X-Forwarded-Proto: https`
- Do not expose the Node process directly to the internet

## Environment variables

See [.env.example](.env.example).

## Scripts

| Command | Description |
|---------|-------------|
| `npm start` | Run server |
| `npm run dev` | Run with file watch |
| `npm run db:init` | Create/upgrade database schema |

## Architecture

```
src/
  server.js       # Entry point
  app.js          # Express setup & middleware
  config.js       # Validated configuration
  db/             # SQLite access layer
  middleware/     # Auth, CSRF, rate limits, validation
  routes/         # Auth and notes handlers
  validation/     # Zod schemas
views/            # EJS templates (HTML-escaped output)
public/           # Static assets (CSP-compatible)
```

## Security checklist before go-live

- [ ] `SESSION_SECRET` is unique and ≥32 characters
- [ ] HTTPS enabled end-to-end
- [ ] `NODE_ENV=production`
- [ ] `TRUST_PROXY=true` behind reverse proxy
- [ ] `npm audit` shows no high/critical issues (or documented exceptions)
- [ ] Database directory not world-readable
- [ ] Firewall allows only proxy → app traffic

**No application is “100% secure.”** This project implements industry-standard controls; ongoing patching, monitoring, and infrastructure hardening remain your responsibility.
