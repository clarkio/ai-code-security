# Secure Notes (Express + SQLite)

A production-ready, security-focused notes app with authentication, CSRF, input validation, rate limiting, and hardened headers.

## Features

- Argon2id password hashing
- Session-based auth with secure cookies and SQLite store
- CSRF protection on all forms
- Helmet with strong CSP and security headers
- Strict input validation (Zod)
- Rate limiting (global + sensitive routes)
- SQLite persistence with WAL, foreign keys, constraints
- No inline scripts/styles; CSP-friendly

## Quickstart

1. Create .env:

```
NODE_ENV=development
PORT=3000
SESSION_SECRET=<generate a long random string>
DATABASE_FILE=./data/notes.db
TRUST_PROXY=false
```

2. Install and run:

```
npm install
npm run dev
```

Visit http://localhost:3000

## Production

- Set `NODE_ENV=production`, a strong `SESSION_SECRET`, and `TRUST_PROXY=true` if behind a reverse proxy. Ensure TLS termination at proxy.
- Run `npm audit --production` during CI, keep dependencies patched.
- Backup `data/` regularly; DB uses WAL and foreign keys.

## Docker

```
docker build -t secure-notes .
docker run --rm -p 3000:3000 --env-file .env -v $(pwd)/data:/app/data secure-notes
```

## Security Notes

- Password min length 12, Argon2id with sensible defaults
- CSRF tokens bound to session; cookie is httpOnly, sameSite=lax, secure in production
- CSP blocks inline scripts/styles, frames, objects; images limited to self+data
- Inputs validated and length-limited server-side; database enforces constraints
- Auth routes get tighter rate limits; mutations on notes are rate limited

## License

MIT
