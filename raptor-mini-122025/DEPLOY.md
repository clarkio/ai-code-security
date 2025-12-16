# Deployment & Hardening Notes

- Use a managed Postgres or secure self-hosted instance. Use TLS and strong passwords.
- Terminate TLS at load balancer or reverse proxy (nginx, Traefik) and forward traffic to HTTP app.
- Set `NODE_ENV=production` and `TRUST_PROXY=true` in your environment.
- Use a secrets manager (AWS Secrets Manager, Vault) for `SESSION_SECRET`, DB creds, and other secrets.
- Set up logging to a centralized system (ELK, Datadog) and capture failed logins.
- Configure monitoring and alerting for anomalous behavior.
- Run vulnerability scans and apply updates regularly.
- Consider switching session store to Redis for performance; ensure Redis is secured.
- Do not run the Node container as root. This Dockerfile creates a non-root user.

If you'd like, I can add a Helm chart, or an example Terraform configuration for production infrastructure.
