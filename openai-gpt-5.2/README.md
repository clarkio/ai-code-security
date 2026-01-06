# Secure Notes (Express + Prisma)

A simple, production-minded notes web app with create/update/delete notes.

## Security features

- Encrypted, `HttpOnly` cookie sessions (iron-session)
- CSRF protection (double-submit cookie via `csrf-csrf`)
- Strong HTTP headers + CSP via Helmet
- Per-user authorization checks on every note
- Rate limiting on auth endpoints and globally
- Input validation with Zod
- Safe server-side rendering with EJS auto-escaping

## Quick start

1. Install deps: `npm install`
2. Create env: copy `.env.example` to `.env` and set `SESSION_PASSWORD`, `CSRF_SECRET`
3. Initialize DB:
   - `npm run prisma:generate`
   - `npx prisma migrate dev --name init`
4. Run: `npm run dev`

## Production notes

- Set `NODE_ENV=production`
- Set `COOKIE_SECURE=true` and run behind HTTPS
- Set `TRUST_PROXY=true` if behind a reverse proxy (recommended)
- Use Postgres in production (`DATABASE_URL=postgresql://...`)
- Rotate `SESSION_PASSWORD` and `CSRF_SECRET` if compromised

## Important

No software can be guaranteed "100% safe". This repo aims for strong, practical security defaults and clear deployment guidance, but you must still:

- Keep dependencies updated
- Use HTTPS everywhere
- Monitor logs and rate limits
- Run security scanning in CI (SCA/SAST)
