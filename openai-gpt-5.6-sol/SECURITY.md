# Security Policy

## Security is a process, not a guarantee

This repository is designed to reduce common web-application risks, but it is not and cannot be guaranteed 100% secure. Passing tests or `npm audit` does not prove the absence of vulnerabilities. The deployment environment, proxy chain, database, identities, secrets, dependencies, monitoring, and operating procedures are part of the security boundary.

Do not use this software for sensitive, regulated, or high-impact data without a deployment-specific threat assessment, independent code review, penetration test, privacy review, and an accountable operational owner.

## Supported versions

Only the current default branch is intended to receive security fixes. Deploy an immutable, reviewed commit and keep a record of the image digest, dependency lockfile, configuration, and migration version in each environment. Forks and modified deployments are the operator's responsibility.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, pull request, log excerpt, or chat message.

- If this repository has GitHub private vulnerability reporting enabled, use **Security -> Advisories -> Report a vulnerability**.
- Otherwise, contact the deployment owner through its documented private security/incident channel.
- Include affected commit/version, impact, prerequisites, minimal reproduction steps, and suggested mitigation. Remove credentials, session IDs, note contents, personal data, and exploit traffic against systems you do not own.

This repository does not define a universal security contact. Every production operator must publish and monitor a private reporting channel and response expectations before launch. Acknowledge reports promptly, preserve confidentiality, coordinate remediation, and disclose only after affected operators have a reasonable opportunity to patch.

## Threat model

### Assets

- User email addresses, password hashes, notes, and server-side session records
- Session-signing secrets, database credentials, TLS keys, backups, and logs
- Application/database integrity and service availability
- Build pipeline, source, lockfile, container image, and deployment configuration

### Trust boundaries

```text
untrusted browser/Internet
          |
          v
trusted TLS edge and fixed proxy chain
          |
          v
Node/Express process ----> log/monitoring platform
          |
          v
trusted PostgreSQL service and backup system
```

CI, the artifact registry, secret manager, administrators, and the deployment control plane are additional privileged boundaries even though they are not shown.

### In-scope attackers and failures

The application includes mitigations for unauthenticated Internet attackers, malicious authenticated users trying to access another user's notes, common CSRF/XSS/SQL-injection/session-fixation attempts, malformed input, password guessing, stale concurrent edits, accidental secret logging, and limited low-volume resource abuse. It also fails startup on important insecure production configuration.

The design does not by itself defeat a compromised host, database, CI runner, registry, dependency, administrator, TLS edge, secret manager, user device, or email account. It does not promise availability during volumetric denial of service or a cloud/region/PostgreSQL outage.

### Required assumptions

Security claims depend on all of these remaining true:

- `NODE_ENV=production`, `PUBLIC_ORIGIN`, `TRUST_PROXY_HOPS`, and `TRUST_PROXY_CIDRS` accurately describe the only route to the app; at least one trusted proxy terminates TLS because the bundled server uses plain HTTP.
- The application cannot be reached around the trusted edge, and the edge overwrites forwarding headers.
- Public traffic uses correctly configured HTTPS; PostgreSQL uses authenticated TLS with a trusted CA.
- Production secrets are random, private, consistently deployed, monitored, and rotated.
- The runtime and database identities are least-privileged and their control planes require strong administrator authentication.
- Supported Node.js/PostgreSQL releases, OS packages, application dependencies, and container images are continuously patched and scanned.
- Backups are protected and restore-tested, logs and alerts are monitored, and an incident responder is available.
- Templates continue to use escaped EJS output for untrusted values; new routes preserve authentication, ownership, validation, and CSRF middleware.

## Implemented controls

### Authentication and sessions

- Passwords are hashed with Argon2id and never intentionally logged. Stored Argon2 parameters are bounded before verification, and at most four password jobs run concurrently in one process.
- Unknown-user login performs a dummy Argon2 verification to reduce obvious timing differences.
- Login errors are generic. Session IDs are regenerated after successful login to mitigate fixation; registration does not authenticate the new account.
- Session state is stored in PostgreSQL; the browser receives a signed opaque identifier.
- Production cookies use the `__Host-` prefix and `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and high priority attributes.
- Authenticated sessions have both a rolling cookie idle timeout and a server-enforced maximum age measured from login.
- Logout destroys the server-side session and clears the cookie.
- Login/registration routes have a process-local IP limiter; note writes have a process-local authenticated-user limiter.

### Authorization and data access

- Notes routes require a session. Reads, updates, and deletes include both note ID and authenticated user ID, reducing insecure direct-object-reference risk.
- SQL uses positional parameters rather than string interpolation.
- PostgreSQL constraints duplicate important length, uniqueness, ownership, and version invariants.
- Note creation quotas are serialized per user with a transaction advisory lock.
- Updates use a version predicate and return a conflict rather than silently overwriting a concurrent change.

### Request and browser protections

- State-changing routes accept only small URL-encoded forms and require a session-bound cryptographic CSRF token. Cross-site Fetch Metadata and mismatched `Origin` values are rejected when supplied.
- Zod strict schemas reject unknown or malformed form fields; request size and parameter counts are capped.
- EJS escapes displayed user values. Unescaped template operations are limited to static application-owned partial includes.
- The Content Security Policy permits no scripts, frames, objects, external styles, fonts, images, or connections. Helmet also sets HSTS in production, framing, MIME-sniffing, referrer, and related headers.
- Production user routes require Express to see HTTPS and require the request `Host` to exactly match `PUBLIC_ORIGIN`. Fixed-response health probes are exempt for private orchestrator access and must remain network-restricted.
- Static serving denies dotfiles and directory indexes. Dynamic/authenticated responses set `Cache-Control: no-store`.
- HTTP parser/server timeouts and a maximum requests-per-socket value limit some slow-client resource use.

### Operations and diagnostics

- Configuration is schema-validated and important unsafe production values fail startup. Production requires `verify-full`, at least one proxy hop, and rejects `NODE_TLS_REJECT_UNAUTHORIZED=0`; database URL query parameters/fragments are rejected so they cannot override TLS and timeout settings.
- Logs contain generated request IDs and sanitized paths; cookie, authorization, password, hash, and CSRF fields are configured for redaction.
- Liveness does not depend on PostgreSQL; readiness returns failure when PostgreSQL cannot answer.
- Shutdown stops accepting work, closes idle connections, applies a bounded drain period, and closes the database pool.
- Migrations use a global advisory lock, per-file checksums, recorded history, and transactions around each unapplied file.
- The container build uses a lockfile, prunes development dependencies in the runtime stage, and runs as the pre-existing unprivileged `node` account.

## Known limitations and residual risks

- **No absolute assurance:** the code has not, merely by being present here, received an independent audit or deployment-specific penetration test.
- **Process-local rate limits:** counters reset on restart and are not shared across replicas. The authentication limiter counts all login and registration attempts but is keyed only by IP within one process. A public deployment needs edge/shared login and registration controls, account quotas, and DDoS protection.
- **Limited session management:** authenticated sessions have an absolute age limit, but it is tied to the same setting as the rolling idle timeout. There is no user-facing device/session inventory or global user logout.
- **No MFA or account recovery controls:** there is no MFA, email verification, password reset, compromised-password screening, SSO, or administrator lifecycle. Public registration can be abused.
- **Password policy is limited:** passwords are length-bounded but are not checked against breached-password corpora. Argon2 work factors must be benchmarked and revisited as hardware changes.
- **Plaintext application data:** notes must be readable by the app and database. There is no application-level/end-to-end encryption, per-note key management, or protection from a privileged database/host operator.
- **Metadata and privacy:** emails, timestamps, IP addresses in operational logs, note sizes, and access patterns may be personal or sensitive data. Retention, deletion, export, consent, and regulatory workflows are deployment responsibilities.
- **No mutation audit trail:** request logs are not a durable user-action audit log, and note contents/history are not version-retained after update/delete.
- **Database TLS still depends on trust configuration:** production accepts only `DATABASE_SSL=verify-full`, but operators must still provide the correct CA trust and a certificate matching the database hostname.
- **Migration operations remain privileged:** the default container command serves without migrating. Production must reliably run and monitor a separate migration job with a migration role before starting the restricted runtime role.
- **Proxy topology remains a boundary:** source CIDRs and hop counts are both checked, but trust is still unsafe if reviewed CIDRs are overly broad, proxy paths have unexpected lengths, forwarding headers are appended incorrectly, or backend network controls permit bypass from a trusted range.
- **Availability:** PostgreSQL is a synchronous dependency for sessions and data. In-process limits do not stop distributed or volumetric attacks. The app has no queue, circuit breaker, multi-region replication, or built-in disaster recovery.
- **Dependency/supply-chain risk:** a clean audit only means the selected advisory database reported no matching issue at that moment. It does not detect malicious packages, unknown vulnerabilities, compromised actions/images, or unsafe transitive behavior.
- **Browser/client compromise:** CSRF, cookie, and CSP controls do not protect a user whose browser, device, extensions, credentials, or active session are compromised.
- **Enumeration side channels require review:** registration intentionally gives new and duplicate addresses the same HTTP outcome, and login uses generic errors plus dummy password work. This has not been formally proven constant-time across the full proxy, application, and database stack, so statistical side channels remain possible.
- **Security headers have operational consequences:** production HSTS includes all subdomains. A misconfigured sibling subdomain may become unreachable over HTTP after a browser caches the policy.

## Production security checklist

Before each launch or material architecture change:

- [ ] Independent review and penetration testing cover the deployed commit, configuration, proxy chain, authentication flows, and infrastructure.
- [ ] Threat model, data classification, privacy/legal requirements, RPO/RTO, and abuse cases are approved by named owners.
- [ ] `NODE_ENV=production`; `PUBLIC_ORIGIN` is the exact HTTPS origin; plaintext traffic redirects at the edge.
- [ ] The app is not publicly reachable except through one fixed trusted proxy path; forwarding headers are overwritten; `TRUST_PROXY_HOPS` and narrow `TRUST_PROXY_CIDRS` values are verified with integration tests from every network path.
- [ ] TLS configuration, certificates, HSTS impact, DNS, edge request limits, and DDoS protections are reviewed.
- [ ] PostgreSQL is private, patched, encrypted, certificate-validated with `verify-full`, monitored, and restricted by network and least-privilege roles. The runtime role can read `app_migrations` for readiness but cannot change the schema.
- [ ] A separate migration job/role runs reviewed append-only migrations before restricted application replicas start.
- [ ] Encrypted backups and point-in-time recovery meet RPO/RTO, alerts are active, and a recent restore drill succeeded.
- [ ] Database/session secrets come from a managed store, are unique per environment, have rotation owners, and are absent from source, image layers, CI output, and logs.
- [ ] Shared edge/distributed limits cover login, registration, writes, total traffic, concurrency, and body size; account creation has an explicit abuse policy.
- [ ] Central logs, metrics, traces as appropriate, request-ID search, dashboards, alerts, retention, access controls, and on-call escalation are tested.
- [ ] Main-branch protection requires review and CI. Dependencies, lockfile changes, images, licenses, SBOM, artifact signatures/provenance, and vulnerability alerts are reviewed.
- [ ] Runtime is non-root, resource-limited, minimally privileged, immutable/read-only where possible, and deployed from a pinned digest.
- [ ] Security reporting, incident response, user support, session revocation, credential rotation, rollback, and disaster-recovery procedures have owners and have been rehearsed.

## Incident response notes

If compromise is suspected, prioritize containment over seamless user experience:

1. Remove the affected deployment from traffic or block the abused path while preserving evidence.
2. Record times, deployed digests/configuration, request IDs, relevant sanitized logs, database audit records, and who performed each response action. Do not copy note contents or credentials unnecessarily.
3. Rotate exposed database/TLS/platform credentials and session secrets. To invalidate all web sessions, remove all rows from `user_sessions` using an authorized, logged database procedure.
4. Determine whether source, CI, artifacts, hosts, proxies, database, backups, logs, or user data were accessed or modified. Do not assume rebuilding the app alone removes persistence.
5. Patch and independently validate the root cause, restore from known-good artifacts/data where necessary, and monitor for recurrence before reopening traffic.
6. Follow applicable contractual and legal notification requirements and conduct a blameless post-incident review with tracked corrective actions.

Never run destructive database or key-rotation procedures without confirming the environment, backups, authorization, and recovery plan.
