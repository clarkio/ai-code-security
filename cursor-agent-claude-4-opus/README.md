# Secure Notes Application

A production-ready Node.js web application for managing notes with comprehensive security measures.

## 🔒 Security Features

This application has been built with security as the top priority, implementing multiple layers of protection:

### Authentication & Authorization
- **JWT-based authentication** with secure token generation and validation
- **Bcrypt password hashing** with configurable rounds (default: 12)
- **Account lockout** after 5 failed login attempts
- **Session management** with secure cookies
- **Password strength requirements** enforced

### Input Validation & Sanitization
- **Express-validator** for comprehensive input validation
- **DOMPurify** for XSS prevention in user content
- **SQL injection prevention** through Sequelize ORM parameterized queries
- **NoSQL injection prevention** with express-mongo-sanitize
- **Request size limiting** to prevent DOS attacks

### Security Headers & Middleware
- **Helmet.js** for security headers (CSP, HSTS, X-Frame-Options, etc.)
- **CORS** with configurable origins
- **Rate limiting** on all endpoints with stricter limits on auth endpoints
- **CSRF protection** using double-submit cookie pattern
- **HPP** (HTTP Parameter Pollution) prevention

### Data Protection
- **Soft deletes** for data recovery
- **Audit trails** with timestamps and user tracking
- **Environment-based configuration** for secrets
- **Secure session storage** in database

### Additional Security Measures
- **Error handling** that doesn't expose sensitive information
- **Security event logging**
- **Content Security Policy** with violation reporting
- **HTTPS enforcement** in production
- **Secure cookie settings** (httpOnly, secure, sameSite)

## 📋 Prerequisites

- Node.js >= 14.0.0
- npm >= 6.0.0

## 🚀 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd cursor-agent-claude-4-opus
```

2. Install dependencies:
```bash
npm install
```

3. Copy the example environment file:
```bash
cp .env.example .env
```

4. Generate secure secrets:
```bash
npm run generate-secrets
```

5. Update `.env` file with the generated secrets and configure other settings as needed.

## ⚙️ Configuration

### Environment Variables

**CRITICAL**: You MUST change the following before deploying to production:

- `SESSION_SECRET`: Session encryption key (use generated value)
- `JWT_SECRET`: JWT signing key (use generated value)
- `NODE_ENV`: Set to `production` for production deployment
- `SESSION_SECURE`: Set to `true` when using HTTPS
- `ALLOWED_ORIGINS`: Set to your actual domain(s)
- `ENABLE_TRUST_PROXY`: Set to `true` if behind a reverse proxy

### Database

The application uses SQLite by default for simplicity. For production deployments with high traffic, consider migrating to PostgreSQL or MySQL.

## 🏃 Running the Application

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

The application will be available at `http://localhost:3000` (or the port specified in `.env`).

## 📝 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/profile` - Get current user profile
- `PUT /api/auth/profile` - Update user profile
- `POST /api/auth/refresh` - Refresh JWT token
- `GET /api/auth/csrf` - Get CSRF token

### Notes
- `GET /api/notes/public` - Get public notes
- `GET /api/notes/my` - Get user's notes (auth required)
- `GET /api/notes/:id` - Get specific note
- `POST /api/notes` - Create note (auth required)
- `PUT /api/notes/:id` - Update note (auth required, owner only)
- `DELETE /api/notes/:id` - Delete note (auth required, owner only)
- `GET /api/notes/tags/all` - Get all user's tags (auth required)

## 🚨 Production Deployment Checklist

### Before Deployment

1. **Generate new secrets**:
   ```bash
   npm run generate-secrets
   ```

2. **Update production .env file**:
   - Set `NODE_ENV=production`
   - Set `SESSION_SECURE=true`
   - Set strong, unique values for all secrets
   - Configure `ALLOWED_ORIGINS` with your domain
   - Set `ENABLE_TRUST_PROXY=true` if using reverse proxy

3. **Use HTTPS**:
   - Deploy behind a reverse proxy (nginx, Apache) with SSL
   - Or use a cloud provider that handles SSL (Heroku, AWS, etc.)

4. **Security headers check**:
   - Verify all security headers are properly set
   - Test with tools like securityheaders.com

5. **Database security**:
   - Use a production-grade database (PostgreSQL/MySQL)
   - Enable SSL for database connections
   - Use strong database passwords
   - Regular backups

6. **Monitoring**:
   - Set up error tracking (Sentry, etc.)
   - Monitor rate limit violations
   - Track authentication failures
   - Set up alerts for security events

### Nginx Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

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

## 🧪 Security Testing

Before going to production, test the following:

1. **Authentication flows**:
   - Registration with weak passwords (should fail)
   - Login with incorrect credentials
   - Account lockout after failed attempts
   - Token expiration

2. **Input validation**:
   - XSS attempts in notes
   - SQL injection attempts
   - Large payload uploads
   - Invalid data types

3. **Authorization**:
   - Accessing other users' private notes
   - Modifying/deleting other users' notes
   - Accessing authenticated endpoints without token

4. **Rate limiting**:
   - Excessive requests to endpoints
   - Brute force attempts on login

## 🤝 Contributing

When contributing to this application, please ensure:

1. All security measures remain intact
2. New endpoints have proper authentication/authorization
3. All inputs are validated and sanitized
4. Security headers are not weakened
5. No secrets are committed to the repository

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

While this application implements numerous security best practices, no system is 100% secure. Always:
- Keep dependencies updated
- Monitor for security advisories
- Conduct regular security audits
- Follow the principle of least privilege
- Implement defense in depth

## 🆘 Support

For security concerns or vulnerabilities, please contact the security team immediately. Do not open public issues for security vulnerabilities.