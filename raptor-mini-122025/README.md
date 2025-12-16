# Secure Notes App 🔒

This repository contains a secure, production-ready Node.js notes application with authentication and CRUD operations for notes.

## Security-first design highlights ✅

- Strong password hashing (Argon2)
- Secure session cookies (HttpOnly, Secure in production, SameSite=Lax)
- Server-side sessions stored in PostgreSQL
- CSRF protection via csurf (fetch token from `/api/csrf-token` and send it in `X-CSRF-Token` for state-changing requests)
- Rate limiting for API
- Input validation with Joi
- Helmet for security headers + CSP advice
- DB queries via Knex (prevents SQL injection)
- Limits on JSON body size

## Getting started (local)

1. Copy `.env.example` -> `.env` and set values.
2. Start a PostgreSQL instance (docker-compose included):

   docker-compose up -d

3. Install and migrate:

   npm install
   npm run migrate
   npm start

## Running tests

npm test

## Deployment notes

- Terminate TLS at a reverse-proxy (Traefik, nginx, cloud load balancer). Do NOT set cookie secure=false in prod.
- Use strong SESSION_SECRET (at least 32 random chars). Rotate secrets periodically.
- Ensure `TRUST_PROXY=true` when behind a proxy so secure cookie flags work.

## Security checklist

See SECURITY.md for detailed recommendations and checklist.
