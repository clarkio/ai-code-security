# Security Policy

This project is a hardened starter app, not a formal security certification.

## Supported Version

Only the current `main` branch is supported.

## Reporting a Vulnerability

Do not open public issues for suspected vulnerabilities. Report them through your private security process and include:

- Impacted route or component.
- Steps to reproduce.
- Expected and actual behavior.
- Relevant logs without passwords, session cookies, or note contents.

## Deployment Checklist

- Use HTTPS only.
- Set `NODE_ENV=production`.
- Set `APP_ORIGIN` to the exact public origin.
- Keep `SESSION_COOKIE_SECURE=1`.
- Set `TRUST_PROXY=1` only when running behind a trusted reverse proxy.
- Run `npm audit --omit=dev` in CI.
- Keep Node.js and dependencies patched.
- Back up and restrict access to the SQLite database.
- Monitor failed logins and unusual request volumes.
