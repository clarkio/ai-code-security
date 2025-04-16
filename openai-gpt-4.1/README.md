# Secure Notes App

A production-ready, security-hardened Node.js app for managing notes.

## Features
- User authentication (session-based)
- Create, update, delete notes
- CSRF protection
- Input validation and sanitization
- Secure HTTP headers (helmet)
- Rate limiting
- Secure session cookies

## Security Checklist
- [x] All user input validated and sanitized
- [x] CSRF protection enabled
- [x] HTTPS enforced in production
- [x] Secure session management
- [x] No sensitive data in codebase
- [x] Rate limiting enabled
- [x] Helmet for HTTP headers

## Setup
1. Copy `.env.example` to `.env` and set values.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the app:
   ```bash
   npm start
   ```

## Deployment
- Use a process manager (e.g., PM2) and reverse proxy (e.g., NGINX) with HTTPS.
- Set strong `SESSION_SECRET` in `.env`.
- Run as non-root user.

## Security Notes
- Do not expose `.env` or `*.sqlite` files.
- Keep dependencies up to date.
- Regularly audit for vulnerabilities.

---

**Your job is safe!**
