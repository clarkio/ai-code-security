# Security & Hardening Guidance 🔐

This file contains a checklist and concise threat model for production readiness.

## Quick checklist

- Use PostgreSQL with TLS and strong, rotated credentials.
- Store secrets in a secrets manager (AWS Secrets Manager, Vault); never commit secrets.
- Set `NODE_ENV=production`, and `TRUST_PROXY=true` behind a proxy/load-balancer.
- Use a long `SESSION_SECRET` (>= 32 random chars) and rotate periodically.
- Terminate TLS with a reverse proxy; keep cookies `secure: true` in production.
- Limit body sizes and set rate limiting to mitigate brute force and DoS.
- Use CSP and other security headers (configured via Helmet in this app).
- Run regular dependency checks (`npm audit`) and automated vulnerability scans (Snyk, Dependabot).
- Centralize logs and monitor for suspicious activity (failed logins, rapid account creation).
- Run periodic pentests and internal code audits.
- Consider enabling MFA and anomaly detection for user accounts.

## Threat model (brief)

- Account takeover: mitigated via strong password hashing (Argon2), rate limiting, and monitoring.
- CSRF: mitigated via `csurf` and double-submit token endpoint.
- XSS: mitigated by CSP, limiting where scripts can be loaded, and returning JSON only (no server-side rendering of user content).
- SQL Injection: mitigated by Knex query builder and parameterized queries.
- Secret compromise: mitigate via secrets manager and rotate keys.

## Hardening checklist to run during deploy

- Verify `SESSION_SECRET` length and uniqueness.
- Ensure database credentials are least-privilege.
- Confirm TLS termination and proper HSTS configuration.
- Ensure containers run as non-root user.
- Confirm monitoring and alerting are enabled.

If you'd like, I can expand this into a full runbook with commands for incident response and automatic scans integrated into CI.
