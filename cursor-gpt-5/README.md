## Secure Notes App

Secure Node.js notes app with authentication, CSRF protection, input validation, rate limiting, and hardened HTTP headers.

### Requirements

- Node.js 18.17+

### Setup

1. Install dependencies: `npm install`
2. Run in dev: `npm run dev`
3. Visit `http://localhost:3000`

Optional `.env` keys: `PORT`, `SESSION_SECRET`, `TRUST_PROXY`, `DB_PATH`, `SESSION_DB_PATH`, `SESSION_COOKIE_NAME`.

### Production

- Set `NODE_ENV=production` and a strong `SESSION_SECRET`.
- Use HTTPS; if behind a proxy, set `TRUST_PROXY=true`.
- Run: `npm start`

### Docker

Build: `docker build -t secure-notes .`
Run: `docker run --rm -p 3000:3000 -e NODE_ENV=production -e SESSION_SECRET=<stronghex> -v $(pwd)/data:/app/data secure-notes`
