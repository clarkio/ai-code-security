# Secure Notes

Small Express application for creating, editing, and deleting notes with conservative security defaults.

## Security posture

- Session-based authentication gates every notes route.
- Passwords are verified against an `scrypt` hash instead of a plaintext secret.
- All state-changing requests require a synchronizer CSRF token.
- Inputs are length-limited and validated before reaching the persistence layer.
- Notes are written to disk with atomic replace writes to avoid partial-file corruption.
- Helmet sets strict security headers, including CSP and `frame-ancestors 'none'`.
- Login and general traffic are rate-limited.
- Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` in production.
- Request logs redact cookies and authorization headers.

## Run locally

1. Install dependencies:

   ```bash
   npm install
   ```

2. Generate a password hash:

   ```bash
   npm run hash-password
   ```

3. Copy `.env.example` to `.env` and fill in the secrets.

4. Start the app:

   ```bash
   npm start
   ```

During local development, if you do not provide credentials, the app falls back to `admin` / `change-me-now`. Do not rely on those defaults outside a local machine.

## Scripts

- `npm start` starts the server.
- `npm test` runs the automated HTTP tests.
- `npm run hash-password` prints a password hash for `.env`.

## Deployment notes

- Set `NODE_ENV=production`.
- Set a long random `SESSION_SECRET`.
- Set `ADMIN_PASSWORD_HASH` from `npm run hash-password`.
- If you deploy behind a reverse proxy or load balancer, set `TRUST_PROXY=1`.
- Terminate TLS before the app or in front of it. This app assumes HTTPS in production.
- Keep the host patched and monitor logs. No web app can honestly guarantee absolute safety without operational controls.
