# Secure Notes Application

A production-ready, security-focused Node.js notes application.

## 🔒 Security Features

This application implements comprehensive security measures following OWASP guidelines:

### Authentication & Authorization

- **Bcrypt Password Hashing**: 12 rounds of bcrypt for secure password storage
- **JWT Authentication**: Short-lived access tokens (15 min) with secure refresh token rotation
- **Account Lockout**: Automatic lockout after 5 failed login attempts (15 min duration)
- **Timing Attack Prevention**: Constant-time password comparison

### Input Validation & Sanitization

- **express-validator**: Comprehensive input validation on all endpoints
- **XSS Prevention**: All user content is sanitized using the `xss` library
- **SQL Injection Prevention**: 100% parameterized queries using better-sqlite3
- **HPP Protection**: HTTP Parameter Pollution protection

### HTTP Security Headers (Helmet)

- **Content-Security-Policy**: Strict CSP preventing XSS and code injection
- **X-Frame-Options**: DENY - prevents clickjacking
- **X-Content-Type-Options**: nosniff - prevents MIME type sniffing
- **Strict-Transport-Security**: HSTS in production (1 year, includeSubDomains)
- **Referrer-Policy**: strict-origin-when-cross-origin
- **X-XSS-Protection**: Enabled in browsers

### Rate Limiting

- **General**: 100 requests per 15 minutes per IP
- **Authentication**: 5 attempts per 15 minutes (login/register)

### Session & Cookie Security

- **httpOnly Cookies**: Prevents JavaScript access to session cookies
- **Secure Flag**: Cookies only sent over HTTPS (production)
- **SameSite=Strict**: CSRF protection via cookie attribute

### Additional Security

- **CORS**: Strict origin validation
- **Request Size Limits**: 10KB max payload
- **Audit Logging**: All security events logged
- **Secure Error Handling**: No stack traces in production
- **Log Sanitization**: Prevents log injection attacks

## 📋 Prerequisites

- Node.js 18.0.0 or higher
- npm 8.0.0 or higher

## 🚀 Quick Start

### Development

```bash
# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Start development server
npm run dev
```

### Production

```bash
# Install dependencies
npm install --production

# Set environment variables (CRITICAL!)
export NODE_ENV=production
export JWT_SECRET=$(openssl rand -hex 64)
export SESSION_SECRET=$(openssl rand -hex 64)
export COOKIE_SECURE=true

# Start server
npm start
```

## ⚙️ Configuration

### Environment Variables

| Variable                  | Required       | Default               | Description                          |
| ------------------------- | -------------- | --------------------- | ------------------------------------ |
| `NODE_ENV`                | Yes            | development           | Environment (production/development) |
| `PORT`                    | No             | 3000                  | Server port                          |
| `HOST`                    | No             | localhost             | Server host                          |
| `JWT_SECRET`              | **Yes (prod)** | -                     | JWT signing secret (min 32 chars)    |
| `SESSION_SECRET`          | **Yes (prod)** | -                     | Session secret (min 32 chars)        |
| `JWT_EXPIRES_IN`          | No             | 15m                   | Access token expiry                  |
| `JWT_REFRESH_EXPIRES_IN`  | No             | 7d                    | Refresh token expiry                 |
| `RATE_LIMIT_WINDOW_MS`    | No             | 900000                | Rate limit window (ms)               |
| `RATE_LIMIT_MAX_REQUESTS` | No             | 100                   | Max requests per window              |
| `DATABASE_PATH`           | No             | ./data/notes.db       | SQLite database path                 |
| `CORS_ORIGINS`            | No             | http://localhost:3000 | Allowed CORS origins                 |
| `COOKIE_SECURE`           | No             | false                 | Secure cookie flag                   |
| `COOKIE_SAME_SITE`        | No             | strict                | SameSite cookie attribute            |
| `LOG_LEVEL`               | No             | info                  | Logging level                        |

### Generate Secure Secrets

```bash
# Generate JWT_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate SESSION_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## 🔐 Production Deployment Checklist

### Critical Security Steps

- [ ] **Change all default secrets** - JWT_SECRET, SESSION_SECRET
- [ ] **Enable HTTPS** - Use a reverse proxy (nginx) with TLS
- [ ] **Set `NODE_ENV=production`**
- [ ] **Set `COOKIE_SECURE=true`**
- [ ] **Configure CORS_ORIGINS** to your domain
- [ ] **Set up a reverse proxy** (nginx, Caddy)
- [ ] **Enable firewall** - Only expose ports 80/443
- [ ] **Set up monitoring** - Log aggregation and alerting
- [ ] **Database backups** - Regular automated backups
- [ ] **Keep dependencies updated** - Run `npm audit` regularly

### Nginx Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://127.0.0.1:3000;
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

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

### Docker Deployment

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --production

# Copy application
COPY src ./src

# Security: Run as non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001
USER nodejs

# Expose port
EXPOSE 3000

# Start application
CMD ["npm", "start"]
```

## 📊 API Endpoints

### Authentication

| Method | Endpoint               | Description          | Auth Required |
| ------ | ---------------------- | -------------------- | ------------- |
| POST   | `/api/auth/register`   | Register new user    | No            |
| POST   | `/api/auth/login`      | Login user           | No            |
| POST   | `/api/auth/refresh`    | Refresh access token | No            |
| POST   | `/api/auth/logout`     | Logout user          | Yes           |
| POST   | `/api/auth/logout-all` | Logout all devices   | Yes           |
| PUT    | `/api/auth/password`   | Change password      | Yes           |
| GET    | `/api/auth/me`         | Get current user     | Yes           |

### Notes

| Method | Endpoint                   | Description     | Auth Required |
| ------ | -------------------------- | --------------- | ------------- |
| GET    | `/api/notes`               | List all notes  | Yes           |
| GET    | `/api/notes/search?q=term` | Search notes    | Yes           |
| GET    | `/api/notes/:id`           | Get single note | Yes           |
| POST   | `/api/notes`               | Create note     | Yes           |
| PUT    | `/api/notes/:id`           | Update note     | Yes           |
| DELETE | `/api/notes/:id`           | Delete note     | Yes           |

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm test -- --coverage

# Run security audit
npm audit
```

## 📝 Security Audit Checklist

Regular security audits should check:

1. **Dependencies**: `npm audit` - no high/critical vulnerabilities
2. **Secrets**: All production secrets are unique and strong
3. **Logs**: Audit logs are being written and monitored
4. **Access**: Only authorized IPs can access admin functions
5. **Backups**: Database backups are working and tested
6. **Updates**: Node.js and all dependencies are up to date

## 🆘 Security Incident Response

If you discover a security vulnerability:

1. **Do NOT** disclose it publicly
2. Document the vulnerability
3. Assess the impact
4. Apply patches immediately
5. Rotate all secrets
6. Review audit logs
7. Notify affected users if data was compromised

## 📄 License

MIT License - See LICENSE file for details.

---

**⚠️ Security Notice**: This application implements industry best practices for security, but no system is 100% secure. Always:

- Keep dependencies updated
- Monitor security advisories
- Perform regular security audits
- Follow the principle of least privilege
- Have an incident response plan
