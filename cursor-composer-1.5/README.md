# Secure Notes App

A production-ready Node.js web application for creating, updating, and deleting notes. Built with security as the top priority.

## Security Features

| Feature | Implementation |
|---------|----------------|
| **SQL Injection** | All database queries use parameterized statements (prepared statements) |
| **XSS** | EJS auto-escapes output with `<%= %>`; no raw user content rendered |
| **CSRF** | CSRF tokens on all state-changing forms (login, register, create, update, delete) |
| **Session Security** | HttpOnly, Secure (in prod), SameSite=Strict cookies |
| **Password Storage** | bcrypt with 12 rounds |
| **Rate Limiting** | 100 requests per 15 minutes per IP |
| **Security Headers** | Helmet: CSP, HSTS, X-Content-Type-Options, etc. |
| **Input Validation** | express-validator with length limits and format checks |
| **Authorization** | Every note operation checks `user_id`; users cannot access others' notes |

## Quick Start

```bash
npm install
npm run init-db
npm start
```

For development with auto-reload:

```bash
npm run dev
```

## Production Deployment

1. **Set environment variables** (copy `.env.example` to `.env`):

   ```env
   NODE_ENV=production
   PORT=3000
   SESSION_SECRET=<generate with: openssl rand -base64 32>
   DATABASE_PATH=./data/notes.db
   ```

2. **Generate a strong session secret**:
   ```bash
   openssl rand -base64 32
   ```

3. **Run behind HTTPS** – Use a reverse proxy (nginx, Caddy) with TLS. Never expose the app directly over HTTP in production.

4. **Initialize the database** (if not already done):
   ```bash
   npm run init-db
   ```

## Requirements

- Node.js 18+
- No native dependencies (uses sql.js - pure JavaScript SQLite)

## License

MIT
