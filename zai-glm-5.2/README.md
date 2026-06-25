# 🔒 Secure Notes App

A production-ready, security-hardened Node.js notes application. Users can register, log in, and create / read / update / delete their own notes. Every layer of the stack was designed with security as the **first** priority.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Create your environment config
cp .env.example .env
# Edit .env — set SESSION_SECRET to a long random string (64+ chars):
#   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# 3. Run the app (development)
npm run dev

# 4. Or run in production mode
NODE_ENV=production npm start
```

The app listens on `http://localhost:3000` by default.

## Requirements

- **Node.js ≥ 22** (uses the built-in `node:sqlite` module — no native compilation required)
- npm

## Running Tests

```bash
npm test
```

The test suite includes 20 security-focused tests covering SQL injection, XSS, CSRF, IDOR, authentication, rate limiting, and security headers.

## Architecture

```
src/
├── config/
│   ├── env.js            # Environment loading & validation (fails fast on weak secrets)
│   └── security.js       # Helmet, rate limiters, HPP, mongo-sanitize
├── db/
│   ├── database.js       # SQLite connection (node:sqlite), migrations, pragmas
│   └── repository.js     # Data access layer — ALL queries parameterized & user-scoped
├── middleware/
│   ├── auth.js           # requireAuth, attachUser
│   ├── csrf.js           # Custom CSRF token (signed cookie, survives session regen)
│   ├── errorHandler.js   # Centralized error handler (no internal leak in prod)
│   └── validation.js      # express-validator schemas for all inputs
├── routes/
│   ├── auth.js           # Register, login, logout
│   ├── notes.js          # CRUD API for notes (IDOR-protected)
│   └── pages.js          # Server-rendered EJS pages
├── utils/
│   ├── password.js       # bcryptjs hashing (cost factor 12)
│   └── sanitize.js       # HTML stripping & length clamping
├── views/                # EJS templates (auto-escaping)
│   ├── partials/
│   ├── login.ejs
│   ├── register.ejs
│   ├── notes.ejs
│   └── error.ejs
├── public/
│   ├── css/app.css
│   └── js/app.js         # Client JS (textContent only — never innerHTML)
└── server.js             # Express app wiring
```

## Security Measures

This is a comprehensive list of every security control implemented. Each one is tested.

### Authentication & Session

| Control                    | Implementation                                                                                                  |
| -------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Password hashing**       | bcryptjs with cost factor 12 — plaintext passwords are never stored or logged                                   |
| **Password policy**        | Min 12 chars, must include upper, lower, number, and special character                                          |
| **Session fixation**       | Session is regenerated on login and registration (`req.session.regenerate()`)                                   |
| **Session cookies**        | `HttpOnly` (no JS access), `Secure` (HTTPS-only in prod), `SameSite=Strict`, 30-min expiry                      |
| **Session store**          | In-memory for dev; Redis-backed in production (if `REDIS_URL` is set)                                           |
| **User enumeration**       | Login & registration return generic error messages; failed login still runs a bcrypt compare to equalize timing |
| **Brute-force protection** | Auth endpoints rate-limited to 10 attempts per IP per 15 minutes                                                |

### Authorization (IDOR Protection)

| Control                   | Implementation                                                                                                                     |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Ownership at DB level** | Every note query includes `WHERE user_id = ?` — a user can never read, update, or delete another user's note, even by guessing IDs |
| **Auth required**         | All `/api/notes` routes require an authenticated session                                                                           |
| **No global listing**     | `listNotes(userId)` always filters by user — there is no way to list all notes                                                     |

### Input Validation & Sanitization

| Control                | Implementation                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| **Validation**         | express-validator schemas on every input (username, password, title, body)                       |
| **SQL injection**      | All database queries use parameterized prepared statements — no string concatenation             |
| **Note ID validation** | Route params validated with `/^\d+$/` regex (not just `parseInt`, which would accept `1 OR 1=1`) |
| **XSS — stored**       | Note title/body are sanitized to plain text (HTML tags stripped) before storage                  |
| **XSS — reflected**    | EJS templates use `<%= %>` which auto-escapes HTML entities                                      |
| **XSS — DOM**          | Client JS uses `textContent` exclusively — never `innerHTML`                                     |
| **Body size limits**   | JSON & URL-encoded bodies limited to 10KB (DoS protection)                                       |
| **Note length limits** | Title max 200 chars, body max 10,000 chars                                                       |
| **HPP**                | HTTP Parameter Pollution protection via `hpp` middleware                                         |
| **Mongo sanitize**     | Query injection sanitization (defense in depth, even though we use SQL)                          |

### CSRF Protection

| Control                                     | Implementation                                                                     |
| ------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Token-based CSRF**                        | Custom implementation — token stored in a signed, HttpOnly, SameSite=Strict cookie |
| **Survives session regeneration**           | Token is in a cookie (not the session), so it remains valid after login/logout     |
| **Required on all state-changing requests** | POST/PUT/PATCH/DELETE must include `X-CSRF-Token` header matching the cookie       |
| **SameSite=Strict cookies**                 | Session cookie itself provides CSRF defense as a second layer                      |

### HTTP Security Headers (Helmet)

| Header                         | Value                                                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `Content-Security-Policy`      | `default-src 'self'` — no inline scripts, no external origins, `object-src 'none'`, `frame-ancestors 'none'` |
| `Strict-Transport-Security`    | 2 years, includeSubDomains, preload                                                                          |
| `X-Frame-Options`              | `DENY` (clickjacking)                                                                                        |
| `X-Content-Type-Options`       | `nosniff`                                                                                                    |
| `Referrer-Policy`              | `no-referrer`                                                                                                |
| `X-Powered-By`                 | Removed                                                                                                      |
| `Cross-Origin-Opener-Policy`   | `same-origin`                                                                                                |
| `Cross-Origin-Resource-Policy` | `same-origin`                                                                                                |
| `Permissions-Policy`           | All features denied                                                                                          |

### Rate Limiting

| Endpoint                  | Limit                                                         |
| ------------------------- | ------------------------------------------------------------- |
| `/api/*` (global)         | 100 requests per 15 min per IP                                |
| `/api/auth/*`             | 10 requests per 15 min per IP (successful logins don't count) |
| Note create/update/delete | 30 requests per minute per IP                                 |

### Error Handling

- Stack traces and internal error details are **never** sent to clients in production
- All errors are logged server-side via `console.error`
- Generic 500 response in production; detailed only in development

### Environment & Secrets

- The app **refuses to boot** in production if `SESSION_SECRET` is missing or < 64 characters
- The app **refuses to boot** if `SESSION_SECRET` contains placeholder text (`CHANGE_ME`, `xxxx`)
- `.env` is in `.gitignore` — secrets are never committed
- The database file lives in `./data/` (outside the web root)

### Graceful Shutdown

- `SIGTERM` / `SIGINT` triggers a clean shutdown: stops accepting connections, closes the DB, then exits
- `uncaughtException` and `unhandledRejection` are caught and logged

## Production Deployment Checklist

Before deploying, ensure:

- [ ] `NODE_ENV=production` is set
- [ ] `SESSION_SECRET` is a 64+ character random string (not a placeholder)
- [ ] The app is behind a reverse proxy (nginx, Caddy, etc.) with HTTPS
- [ ] `TRUST_PROXY` is set to the number of proxy hops (usually `1`)
- [ ] `REDIS_URL` is set for production session storage (memory store leaks in prod)
- [ ] The `./data/` directory is backed up regularly
- [ ] `npm audit` passes with no high/critical vulnerabilities
- [ ] Rate limits are tuned for your traffic (see `.env.example`)

### Example nginx config

```nginx
server {
    listen 443 ssl http2;
    server_name notes.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Security headers (supplement what Helmet sets)
    add_header X-Frame-Options DENY always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## API Reference

### Authentication

| Method | Path                 | Description                               |
| ------ | -------------------- | ----------------------------------------- |
| `POST` | `/api/auth/register` | Create account — `{ username, password }` |
| `POST` | `/api/auth/login`    | Log in — `{ username, password }`         |
| `POST` | `/api/auth/logout`   | Destroy session                           |

### Notes (all require auth + CSRF token)

| Method   | Path             | Description                       |
| -------- | ---------------- | --------------------------------- |
| `GET`    | `/api/notes`     | List current user's notes         |
| `GET`    | `/api/notes/:id` | Get a single note (only if owned) |
| `POST`   | `/api/notes`     | Create note — `{ title, body }`   |
| `PUT`    | `/api/notes/:id` | Update note (only if owned)       |
| `DELETE` | `/api/notes/:id` | Delete note (only if owned)       |

All state-changing requests require the `X-CSRF-Token` header.

## License

MIT
