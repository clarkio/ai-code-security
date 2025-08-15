Secure Notes App (Node.js)

Environment variables (create .env):

- PORT: server port
- MONGODB_URI: MongoDB connection string
- JWT_SECRET: strong random secret
- COOKIE_SECRET: strong random secret for cookies
- RATE_LIMIT_WINDOW_MS: optional, default 900000
- RATE_LIMIT_MAX: optional, default 100

Scripts:

- npm run dev
- npm start

Security features:

- helmet, CORS with allowlist, rate limiting, strict validation, mongo sanitize, XSS sanitize, JWT auth (HttpOnly cookies), CSRF for form endpoints, secure headers, compression, minimal logging.
