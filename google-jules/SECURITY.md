# Security Policy for google-jules

## Security Overview

The `google-jules` Secure Notes application is designed with security as a primary consideration. We aim to follow best practices for web application security to protect user data and ensure the integrity of the service. This document outlines the security features implemented, considerations for deployment, and how to approach security matters related to this application.

## Security Features Implemented

*   **Authentication:**
    *   Uses JSON Web Tokens (JWTs) for stateless session management.
    *   Passwords are hashed using `bcryptjs` with a work factor of 10 before being stored in the database.

*   **Authorization:**
    *   API endpoints for accessing or modifying notes are protected.
    *   Users can only access and modify notes they own. This is enforced by checking `user_id` in database queries for note operations.

*   **Input Validation:**
    *   All incoming data from user inputs (request bodies, URL parameters) is validated and sanitized using `express-validator`. This helps prevent common injection attacks and ensures data integrity.

*   **Output Encoding:**
    *   As a JSON-based API, the primary responsibility for preventing XSS through output encoding lies with the client-side application consuming the API.
    *   The API sets appropriate `Content-Type: application/json` headers.
    *   The example frontend in the `/public` directory uses basic text node assignment or careful innerHTML construction to prevent XSS for displayed data.

*   **SQL Injection Prevention:**
    *   The application uses `sqlite3` with parameterized queries for all database interactions. This is the standard practice for preventing SQL injection vulnerabilities.

*   **Cross-Site Scripting (XSS) Prevention:**
    *   `helmet` middleware is used, which sets headers like `X-XSS-Protection` to `1; mode=block`.
    *   While `helmet` provides some browser-level XSS protections, the API's main defense is input validation.
    *   Content Security Policy (CSP) is not explicitly configured by default beyond what `helmet` might provide in its default set. For enhanced security, a specific CSP could be added.

*   **Cross-Site Request Forgery (CSRF) Protection:**
    *   `csurf` middleware is implemented for all state-changing endpoints (POST, PUT, DELETE).
    *   Clients must fetch a CSRF token from the `GET /api/auth/csrf-token` endpoint.
    *   This token must be included in the `X-CSRF-Token` header for subsequent state-changing requests. The backend validates this token against a secret stored in a cookie.

*   **Secure Headers:**
    *   `helmet` is used to set various HTTP headers to improve security, including:
        *   `Strict-Transport-Security` (HSTS): Enforces HTTPS (though the server itself doesn't handle TLS termination directly; see Deployment).
        *   `X-Frame-Options`: Protects against clickjacking.
        *   `X-Content-Type-Options`: Prevents browsers from MIME-sniffing a response away from the declared content-type.
        *   `Content-Security-Policy`: Sets a basic policy (can be customized for stricter rules).
        *   `X-DNS-Prefetch-Control`: Controls DNS prefetching.
        *   `Referrer-Policy`: Controls referrer information sent.
        *   `Expect-CT`: For Certificate Transparency.
        *   `X-Powered-By` is removed.

*   **Rate Limiting:**
    *   `express-rate-limit` is used to protect against brute-force attacks.
    *   Separate limiters are applied:
        *   A general limiter for all `/api/` routes.
        *   A stricter limiter for authentication routes (`/api/auth/login`, `/api/auth/register`).

*   **Error Handling:**
    *   A global error handler is implemented.
    *   In production (`NODE_ENV=production`), generic error messages are sent to the client to avoid leaking sensitive stack traces or internal details. Detailed errors are logged on the server.

*   **Logging:**
    *   Comprehensive logging using `winston` for application events and errors.
    *   HTTP request logging using `morgan`, integrated with `winston`.
    *   Logs are written to files (`error.log`, `combined.log`) and to the console in development.

*   **Environment Variables:**
    *   Sensitive configuration, such as `JWT_SECRET`, `CSRF_SECRET`, and `DATABASE_URL`, is managed through environment variables (using a `.env` file for development).

## Security Considerations for Deployment

*   **HTTPS (TLS/SSL):**
    *   **CRITICAL:** The Node.js/Express application itself does not handle TLS termination. It should **always** be deployed behind a reverse proxy (e.g., Nginx, Apache, or a load balancer service from a cloud provider) that is configured to handle HTTPS and terminate TLS connections.
    *   The reverse proxy should then forward requests to the Node.js application over HTTP on the local network.
    *   Ensure HSTS headers set by `helmet` are effective by having a valid HTTPS setup.

*   **Database Security:**
    *   For production, consider using a more robust database system (e.g., PostgreSQL, MySQL) instead of SQLite, depending on scale and requirements.
    *   Use strong, unique credentials for database access.
    *   Restrict database user permissions to the minimum necessary.
    *   Implement regular database backups and a recovery plan.
    *   Ensure the database server is not directly exposed to the internet.

*   **Secrets Management:**
    *   `JWT_SECRET` and `CSRF_SECRET` **must** be strong, unique, and randomly generated strings for production. Do not use default or example secrets.
    *   These secrets should be managed securely (e.g., using a secrets management system like HashiCorp Vault, AWS Secrets Manager, or environment variables injected by the deployment platform). Do not commit them directly into version control.

*   **CORS Configuration:**
    *   In production, configure `CORS_ORIGIN` in your `.env` file to allow requests only from your specific frontend domain(s). Avoid using wildcard `*` for CORS in production.

*   **Dependency Management & Updates:**
    *   Regularly update all dependencies (npm packages) to their latest stable versions to patch known vulnerabilities. Use tools like `npm audit` to identify vulnerabilities.

*   **Firewall:**
    *   Use a host-based or network firewall to restrict incoming traffic to only the necessary ports (e.g., the port your reverse proxy listens on for HTTPS, typically 443). The Node.js application port should generally not be directly exposed to the internet.

*   **Principle of Least Privilege:**
    *   Run the Node.js application with the least privileged user account possible.

*   **Production Logging:**
    *   Ensure `LOG_LEVEL` is set appropriately for production (e.g., `info` or `warn`).
    *   Securely store and manage logs. Implement log rotation and monitoring.

## Reporting Security Vulnerabilities

This is a sample project. If this were a live, public application, a section like this would describe how to responsibly report security vulnerabilities. For example:

"If you discover a security vulnerability within this project, please send an email to [security@example.com](mailto:security@example.com). We will address all legitimate reports and appreciate your efforts to disclose issues responsibly."

---

This `SECURITY.md` provides a comprehensive overview of the security measures in place and best practices for deploying the application securely.The `README.md` and `SECURITY.md` files have been created and updated as per the instructions.

*   `README.md` now contains a detailed overview of the application, its features, tech stack, setup instructions, API endpoints, testing information, and project structure.
*   `SECURITY.md` outlines the security features implemented, provides important considerations for secure deployment, and includes a placeholder for reporting vulnerabilities.

This completes the subtask of updating and creating documentation for the application.
