# Secure Notes API

A production-ready, security-focused Node.js REST API for managing notes with JWT authentication.

## Security Features

This application implements comprehensive security measures:

### Authentication & Authorization
- **JWT-based authentication** with secure token validation
- **Password hashing** using bcrypt with configurable rounds (default: 12)
- **Strong password requirements**: minimum 12 characters, uppercase, lowercase, number, and special character
- **Token expiration** with configurable time-to-live
- **User ownership verification** on all note operations

### Input Validation & Sanitization
- **Express-validator** for all input validation
- **SQL injection prevention** via parameterized queries (no raw SQL)
- **XSS prevention** with automatic HTML escaping
- **Request size limits** (10kb max body size)
- **Input length constraints** on all fields

### Rate Limiting & DDoS Protection
- **General API rate limiting**: 100 requests per 15 minutes per IP
- **Stricter auth rate limiting**: 5 requests per 15 minutes for login/register
- **Configurable windows and limits** via environment variables

### HTTP Security Headers
- **Helmet.js** for comprehensive header security
- **HSTS** (HTTP Strict Transport Security) with preload
- **CSP** (Content Security Policy) configured
- **X-Frame-Options** to prevent clickjacking
- **X-Content-Type-Options** to prevent MIME sniffing
- **Referrer-Policy** for privacy

### CORS Configuration
- **Configurable allowed origins** via environment variables
- **Credentials support** for secure cookie handling
- **Preflight caching** for performance

### Database Security
- **Parameterized queries** throughout (SQL injection prevention)
- **Foreign key constraints** with CASCADE delete
- **WAL mode** for better concurrency
- **Indexed queries** for performance

### Error Handling
- **Generic error messages** to prevent information leakage
- **Structured error responses** without stack traces
- **Comprehensive logging** for security monitoring
- **Graceful degradation** on errors

## Prerequisites

- Node.js >= 18.0.0
- npm or yarn

## Installation

1. Clone the repository and navigate to the project directory:
```bash
cd secure-notes-app
```

2. Install dependencies:
```bash
npm install
```

3. Create environment configuration:
```bash
cp .env.example .env
```

4. **CRITICAL**: Edit `.env` and set a secure JWT_SECRET:
```bash
# Generate a secure random secret (64+ characters recommended)
JWT_SECRET=your_very_long_random_secret_here_minimum_64_characters_long
```

5. Run database migration:
```bash
npm run migrate
```

## Environment Variables

Required variables:
- `JWT_SECRET`: A cryptographically secure random string (minimum 64 characters recommended)
- `NODE_ENV`: Set to `production` for deployment

Optional variables:
- `PORT`: Server port (default: 3000)
- `JWT_EXPIRES_IN`: Token expiration time (default: 1h)
- `RATE_LIMIT_WINDOW_MS`: Rate limit window in milliseconds (default: 900000)
- `RATE_LIMIT_MAX_REQUESTS`: Max requests per window (default: 100)
- `BCRYPT_ROUNDS`: Password hashing rounds (default: 12)
- `CORS_ORIGIN`: Comma-separated list of allowed origins
- `DATABASE_PATH`: Path to SQLite database (default: ./data/notes.db)

## Running the Application

Development mode:
```bash
npm run dev
```

Production mode:
```bash
npm start
```

## API Endpoints

### Authentication

#### Register User
```
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Login
```
POST /api/auth/login
Content-Type: application/json

{
  "username": "johndoe",
  "password": "SecurePass123!"
}
```

Returns a JWT token in the response. Include this token in the Authorization header for protected routes:
```
Authorization: Bearer <token>
```

### Notes (All require authentication)

#### Create Note
```
POST /api/notes
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "My Note",
  "content": "Note content here"
}
```

#### List Notes
```
GET /api/notes?limit=50&offset=0
Authorization: Bearer <token>
```

#### Get Single Note
```
GET /api/notes/:id
Authorization: Bearer <token>
```

#### Update Note
```
PUT /api/notes/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "Updated Title",
  "content": "Updated content"
}
```

#### Delete Note
```
DELETE /api/notes/:id
Authorization: Bearer <token>
```

## Security Deployment Checklist

Before deploying to production, ensure you have:

### 1. Environment Security
- [ ] Set `NODE_ENV=production`
- [ ] Generate a **strong, random JWT_SECRET** (minimum 64 characters)
- [ ] Set `COOKIE_SECURE=true` if using HTTPS
- [ ] Configure `CORS_ORIGIN` to your actual frontend domain(s)
- [ ] Never commit `.env` file to version control

### 2. Infrastructure Security
- [ ] Use HTTPS/TLS in production (required for secure cookies)
- [ ] Configure a reverse proxy (nginx, Apache, or cloud load balancer)
- [ ] Set up proper firewall rules
- [ ] Enable request logging and monitoring
- [ ] Configure database backups
- [ ] Use a process manager (PM2, systemd, etc.)

### 3. Network Security
- [ ] Restrict database file permissions
- [ ] Use a WAF (Web Application Firewall) if available
- [ ] Configure DDoS protection
- [ ] Set up intrusion detection
- [ ] Implement IP whitelisting for admin endpoints if needed

### 4. Operational Security
- [ ] Set up automated security updates
- [ ] Monitor logs for suspicious activity
- [ ] Implement log rotation
- [ ] Set up alerts for failed login attempts
- [ ] Regular security audits
- [ ] Dependency vulnerability scanning (`npm audit`)

### 5. Application Security
- [ ] Review and test all authentication flows
- [ ] Test rate limiting functionality
- [ ] Verify input validation on all endpoints
- [ ] Test SQL injection resistance
- [ ] Verify XSS protection
- [ ] Test CSRF protection (if adding frontend)

## Security Best Practices

### Password Security
- Enforce strong password requirements (already implemented)
- Consider implementing password entropy checking
- Implement account lockout after failed attempts
- Consider adding 2FA/MFA for sensitive operations

### Token Security
- Use short-lived tokens (1 hour recommended)
- Implement refresh token rotation
- Store tokens securely on the client (httpOnly cookies recommended)
- Invalidate tokens on password change
- Implement token blacklisting for logout

### Data Security
- Encrypt sensitive data at rest if needed
- Implement data retention policies
- Regular database backups
- Secure backup storage

### Monitoring & Logging
- Log all authentication attempts
- Monitor for unusual patterns
- Set up alerts for security events
- Regular log analysis
- Implement audit trails for sensitive operations

## Testing Security

### Manual Testing Checklist
- [ ] Test SQL injection attempts on all inputs
- [ ] Test XSS payloads in note content
- [ ] Test authentication bypass attempts
- [ ] Test authorization bypass (accessing other users' notes)
- [ ] Test rate limiting enforcement
- [ ] Test input validation with malformed data
- [ ] Test with oversized payloads
- [ ] Test with special characters and Unicode

### Automated Security Tools
```bash
# Run npm audit for dependency vulnerabilities
npm audit

# Use Snyk for deeper security scanning
npm install -g snyk
snyk test

# Consider using OWASP ZAP for penetration testing
```

## Production Deployment Example (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## License

MIT

## Support

For security issues, please report them privately rather than via public issues.
