# Secure Notes

Secure Notes is a small server-rendered notes application built with Node.js, TypeScript, Express 5, EJS, and PostgreSQL. Users can register, sign in, and create, update, or delete notes. Authentication state is stored server-side in PostgreSQL.

> [!IMPORTANT]
> No application can be guaranteed **100% secure**. This project uses defensive defaults, but safe operation also depends on correct proxy, TLS, database, secret-management, monitoring, patching, and incident-response practices. Before handling sensitive or regulated data, commission an independent security review and penetration test for the actual deployment.

## Architecture

```text
browser -- HTTPS --> trusted edge/reverse proxy --> Node/Express --> PostgreSQL
                       (one fixed path)              (TLS verify-full in production)
```

- Express renders escaped EJS templates; there is no client-side JavaScript.
- PostgreSQL stores users, notes, migration history, and sessions.
- The application exposes `GET /health/live` for process liveness and `GET /health/ready` for database readiness.
- The production image runs as the unprivileged `node` user. Its default command starts only the server; production migrations are a separate deployment step.

## Security highlights

- Argon2id password hashing, bounded stored-hash costs, dummy verification for unknown users, and a four-job process-wide hashing ceiling
- Server-side sessions, login session regeneration, signed opaque cookies, and production `__Host-` cookies
- `HttpOnly`, `Secure` in production, `SameSite=Strict`, rolling session cookies
- Session-bound CSRF tokens plus `Origin` and Fetch Metadata checks on every state-changing route
- Strict input schemas, small form/body limits, PostgreSQL constraints, and parameterized SQL
- Every note query includes the authenticated user ID to enforce ownership
- EJS output escaping, a restrictive Content Security Policy, HSTS in production, and other Helmet headers
- Generic authentication failures and per-process request/authentication/write rate limits
- Optimistic concurrency checks to prevent silent stale-note overwrites
- Structured request IDs and redacted logs; no request bodies, cookies, or query strings are intentionally logged
- Fixed server timeouts, graceful shutdown, note quotas, and transactional/checksummed migrations

These controls reduce risk; they do not remove the operational requirements or residual limitations in [SECURITY.md](SECURITY.md).

## Prerequisites

- Node.js 24 (the package intentionally rejects other major versions)
- npm, using the committed `package-lock.json`
- PostgreSQL 17 for the documented deployment; a compatible maintained PostgreSQL release may also work
- Docker with Compose v2 for the quickest local setup

## Quick start with Docker Compose

The included Compose configuration is for local development only. Its credentials and session secret are public, intentionally weak development values.

```sh
docker compose up --build
```

Open <http://localhost:3000>. The app waits for PostgreSQL, applies migrations, and then starts. Data persists in the `notes-database` volume.

```sh
docker compose down
```

`docker compose down -v` also permanently deletes the local database volume.

## Local development without the app container

1. Create a local PostgreSQL database and role matching `DATABASE_URL` in `.env.example`.
2. Copy `.env.example` to `.env` and replace every placeholder. Generate a session secret with:

   ```sh
   node -e "process.stdout.write(require('node:crypto').randomBytes(48).toString('base64url'))"
   ```

3. Install exactly the locked dependencies, migrate the database, and start the development server:

   ```sh
   npm ci
   npm run db:migrate
   npm run dev
   ```

`dev` and `db:migrate` load `.env` when present. Production commands expect the deployment platform to inject environment variables; they do not load `.env` files.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Run TypeScript directly, loading `.env` when present |
| `npm run typecheck` | Strict TypeScript checking without output |
| `npm test` | Run the security and application tests serially |
| `npm run build` | Compile application and scripts into `dist/` |
| `npm start` | Start compiled code without applying migrations |
| `npm run db:migrate` | Apply source migrations during development |
| `npm run start:migrate` | Apply compiled migrations and start the compiled server |
| `npm run audit` | Fail on high/critical production dependency advisories |
| `npm run check` | Run type checking and tests |

Before `npm start` or `npm run start:migrate`, run `npm run build`. The Docker image performs the build during image creation.

## Configuration

Startup fails closed when required configuration is missing or invalid.

| Variable | Development example/default | Production requirement |
| --- | --- | --- |
| `NODE_ENV` | `development` | Set exactly `production`; enables secure cookies, HTTPS/host checks, HSTS, and production defaults |
| `HOST` | `127.0.0.1` | Bind to the private interface used by the orchestrator, commonly `0.0.0.0` in a container; do not expose it directly to the Internet |
| `PORT` | `3000` | Internal listening port, `1`-`65535` |
| `PUBLIC_ORIGIN` | `http://localhost:3000` | Exact public bare origin, for example `https://notes.example.com`; no path, credentials, query, or fragment |
| `DATABASE_URL` | See `.env.example` | Secret PostgreSQL URL for the role used by this process. Query parameters and fragments are rejected; configure TLS only with `DATABASE_SSL` |
| `DATABASE_SSL` | `disable` | Must be `verify-full` with a trusted CA. `require` would encrypt without authenticating the database endpoint and is rejected in production |
| `SESSION_SECRETS` | Required | Comma-separated secrets, each at least 32 bytes. The first signs new cookies; later values only verify old cookies |
| `SESSION_TTL_MINUTES` | `480` | Cookie idle lifetime and maximum authenticated-session age, from `15` to `10080` |
| `TRUST_PROXY_HOPS` | `0` | Exact, invariant number of trusted proxies between the browser and app, from `0` to `5`; production requires at least `1` |
| `TRUST_PROXY_CIDRS` | empty | Comma-separated explicit CIDR networks containing every trusted proxy; required when `TRUST_PROXY_HOPS` is nonzero |
| `MAX_NOTES_PER_USER` | `100` | Storage/abuse quota, from `1` to `100` |
| `LOG_LEVEL` | `info` | One of `fatal`, `error`, `warn`, `info`, `debug`, `trace`, or `silent` |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | Graceful shutdown deadline, from `1000` to `60000` milliseconds |

Do not commit `.env`. Use the platform's secret manager and restrict who and what can read production values.
Do not set `NODE_TLS_REJECT_UNAUTHORIZED=0`; production startup explicitly rejects it because it disables Node.js TLS certificate verification.

In development and tests, CSRF validation also accepts the request's own same-origin scheme and Host, so loopback aliases such as `localhost` and `127.0.0.1` work. Production remains locked to `PUBLIC_ORIGIN` after the HTTPS and Host guards run.

### Session secret rotation

Generate secrets with a cryptographically secure random generator and encode them as base64url so they contain no commas. To rotate without immediately signing everyone out:

1. Change `SESSION_SECRETS` from `old` to `new,old` on every instance at the same time.
2. Wait longer than the maximum rolling idle period plus deployment skew.
3. Change it to `new`.

Removing the old value sooner invalidates cookies signed with it. A suspected compromise should favor immediate invalidation over a seamless rotation; also delete server-side sessions.

## Production deployment requirements

### TLS and reverse proxies

Terminate public TLS at a controlled edge using TLS 1.2 or newer, redirect plaintext HTTP to HTTPS there, and make the application reachable only from the final proxy or private network. Production requests that Express does not recognize as HTTPS are rejected; the app itself does not perform the HTTP redirect.

The bundled server uses plain `node:http`; it does not terminate TLS. Production therefore requires at least one trusted TLS-terminating proxy. Proxy trust requires both the exact maximum distance and explicit source networks. For example:

- Browser -> one ingress on `10.20.0.0/16` -> app: `TRUST_PROXY_HOPS=1` and `TRUST_PROXY_CIDRS=10.20.0.0/16`.
- Browser -> CDN egress plus ingress -> app: set `TRUST_PROXY_HOPS=2` and list both reviewed egress networks in `TRUST_PROXY_CIDRS`.

The edge chain must discard client-supplied forwarding headers and set authoritative `X-Forwarded-For` and `X-Forwarded-Proto: https` values. The final proxy must forward a `Host` header exactly matching `PUBLIC_ORIGIN`. Use the narrowest stable CIDRs, keep every path at the configured distance, and firewall the backend from all other sources. A CIDR allowlist does not make a broad or bypassable private network trustworthy.

HSTS includes subdomains for one year in production. Ensure every subdomain of the chosen parent domain supports HTTPS before serving this app there.

### PostgreSQL

- Use `DATABASE_SSL=verify-full` and a hostname matching the database certificate. Install the issuing CA in the runtime trust store. Do not use `require` as a substitute for certificate validation.
- Put PostgreSQL on a private network, restrict inbound traffic to application/migration workloads, require strong authentication, patch it promptly, and encrypt disks and backups.
- Use separate roles in production. A migration role should own/alter the schema. The runtime role needs only `CONNECT`, schema `USAGE`, `SELECT`/`INSERT` on `users`, the required `SELECT`/`INSERT`/`UPDATE`/`DELETE` permissions on `notes` and `user_sessions`, and `SELECT` on `app_migrations` for readiness checks. It does not need schema creation or access to unrelated databases.
- Set connection, statement, and idle-transaction limits at the database or proxy as appropriate. Budget for up to 10 pool connections per application instance plus migration/administrative connections.
- Maintain encrypted, access-controlled backups and point-in-time recovery appropriate to the required RPO/RTO. Monitor backup jobs and practice full restores regularly; a backup that has not been restored is unverified.

The image's default command starts `dist/src/server.js` and deliberately does not migrate. Run `node dist/scripts/migrate.js` once as a deployment job with the migration role, then launch replicas with the restricted runtime role. Gate rollout on migration success. Local Compose is different: it overrides the image command with `dist/scripts/start.js` so the development role migrates and then serves.

Migrations are ordered, transaction-wrapped where possible, serialized by a PostgreSQL advisory lock, and recorded with checksums. Add new numbered files; never modify a migration already applied to any environment. Review destructive or locking changes and use expand/migrate/contract rollouts for zero-downtime schema changes.

### Secrets and data

- Store database credentials and session secrets in a managed secret store, inject them at runtime, restrict access, and audit reads.
- Never bake secrets into images or put them in command-line arguments, CI logs, tickets, or chat. The Compose values are not production secrets.
- Rotate credentials on a schedule and immediately after suspected exposure. Test session-secret and database-credential rotation before an incident.
- Notes are plaintext to the application and database. Use infrastructure encryption at rest and limit database/operator access. If the threat model requires protection from database operators or an offline database compromise, add separately reviewed application-level or end-to-end encryption.

### Rate limiting and abuse controls

The built-in limiters use process memory. Their counters reset on restart and are neither coordinated nor cumulative across replicas. The authentication limiter counts every login and registration attempt, but it remains IP-based and process-local. Argon2 work is separately capped at four concurrent jobs per process; excess requests fail temporarily instead of creating unbounded hashing work. A multi-instance or public deployment must still enforce shared limits at the edge or use a reviewed shared rate-limit store, especially for registration and login. Add account-creation quotas, bot controls, and service-wide request/body/concurrency limits appropriate to expected traffic.

Do not rely on IP alone for identity or abuse decisions. Consider NATs, IPv6, privacy proxies, and trusted-forwarding configuration when choosing limits. Load balancing does not require sticky sessions because PostgreSQL is the shared session store.

### Monitoring and operations

- Route JSON logs to an access-controlled, tamper-resistant log platform. Retain the request ID and alert on sustained 5xx, readiness failures, unusual 401/403/409/429 rates, latency, restarts, and shutdown timeouts.
- Monitor PostgreSQL saturation, pool waits, disk/replication health, migration failures, session-table growth, backup age, certificate expiry, and secret-rotation age.
- Use `/health/live` only for liveness and `/health/ready` for traffic readiness. Restrict or separately rate-limit health endpoints at the edge if exposure is unnecessary.
- Health probes are the only production routes exempt from the HTTPS and public-Host guard so a private orchestrator can query the internal HTTP listener. Keep the listener network-private; the endpoints return only a fixed status word.
- Set CPU, memory, process, connection, and filesystem limits. Run an immutable image as non-root with a read-only root filesystem where the platform permits it.
- Keep Node.js, the base image, npm dependencies, PostgreSQL, and the host patched. Rebuild regularly even when application code is unchanged, scan the resulting image, generate an SBOM, sign/provenance-track artifacts, and deploy by digest.
- Rehearse rollback, restore, secret compromise, session invalidation, and database outage procedures. Define an on-call owner and security reporting channel before launch.

## CI

`.github/workflows/ci.yml` uses Node 24 and PostgreSQL 17 to install the lockfile, type-check, validate migrations, test, build, and audit production dependencies. CI is a quality gate, not a security assessment. Protect the main branch, require the workflow, review dependency changes, and configure automated dependency/image scanning.

## Security policy

See [SECURITY.md](SECURITY.md) for the threat model, deployment assumptions, known limitations, vulnerability reporting guidance, and incident checklist.
