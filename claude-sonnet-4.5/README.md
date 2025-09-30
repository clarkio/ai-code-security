# 🔒 Secure Notes Application

A production-ready, security-hardened Node.js web application for creating, updating, and deleting notes.

## ⚠️ CRITICAL SECURITY NOTICE

This application has been built with comprehensive security measures. Before deploying to production:

1. **CHANGE ALL DEFAULT SECRETS** in `.env` file
2. Use strong, randomly generated secrets (minimum 32 characters)
3. Enable HTTPS/TLS in production
4. Use a proper database with encryption at rest (current implementation uses in-memory storage)
5. Implement proper session management with Redis for multi-instance deployments
6. Set up proper monitoring and logging
7. Regular security audits with `npm audit` and consider using Snyk

## 🛡️ Security Features Implemented

### Authentication & Authorization

- ✅ **JWT-based authentication** with secure token generation
- ✅ **Bcrypt password hashing** with configurable rounds (default: 12)
- ✅ **Secure HTTP-only cookies** with SameSite protection
- ✅ **Rate limiting** on authentication endpoints (5 attempts per 15 minutes)
- ✅ **Account lockout** after failed login attempts
- ✅ **Password strength requirements** (uppercase, lowercase, number, special character)

### Input Validation & Sanitization

- ✅ **Express-validator** for comprehensive input validation
- ✅ **XSS protection** using xss-clean middleware
- ✅ **NoSQL injection protection** using express-mongo-sanitize
- ✅ **HTTP Parameter Pollution (HPP) prevention**
- ✅ **Input length limits** to prevent DoS
- ✅ **UUID validation** for resource IDs
- ✅ **HTML entity escaping** in frontend

### HTTP Security Headers

- ✅ **Helmet.js** for security headers
- ✅ **Content Security Policy (CSP)**
- ✅ **HTTP Strict Transport Security (HSTS)**
- ✅ **X-Frame-Options** (clickjacking protection)
- ✅ **X-Content-Type-Options** (MIME sniffing protection)
- ✅ **XSS Filter**

### Rate Limiting & DoS Protection

- ✅ **Global rate limiting** (100 requests per 15 minutes)
- ✅ **Stricter auth endpoint limiting** (5 attempts per 15 minutes)
- ✅ **Request body size limits** (10kb max)
- ✅ **Maximum notes per user** (1000 limit)

### CORS & Cross-Origin Protection

- ✅ **Strict CORS policy** with configurable allowed origins
- ✅ **Credentials handling** for secure cookie transmission
- ✅ **SameSite cookie attribute** for CSRF protection

### Data Protection

- ✅ **Authorization checks** on all protected routes
- ✅ **Resource ownership validation** (users can only access their own notes)
- ✅ **Sensitive data filtering** (passwords never exposed in responses)
- ✅ **Secure session management**

### Error Handling & Logging

- ✅ **Centralized error handling**
- ✅ **Sanitized error messages** (no sensitive info in production)
- ✅ **Request logging** with sensitive data filtering
- ✅ **Graceful shutdown** handling

### Additional Security Measures

- ✅ **Environment variable configuration** (.env file)
- ✅ **Production vs development modes**
- ✅ **Signed cookies** for tamper protection
- ✅ **Trust proxy configuration** for reverse proxy compatibility
- ✅ **Health check endpoint** for monitoring

## 📋 OWASP Top 10 Coverage

1. **Broken Access Control** ✅ - Authorization checks on all routes
2. **Cryptographic Failures** ✅ - Bcrypt for passwords, JWT for tokens
3. **Injection** ✅ - Input validation, sanitization, parameterized queries
4. **Insecure Design** ✅ - Security-first architecture
5. **Security Misconfiguration** ✅ - Helmet, secure defaults, clear documentation
6. **Vulnerable Components** ✅ - Latest dependencies, npm audit
7. **Authentication Failures** ✅ - Strong password policy, rate limiting, lockout
8. **Data Integrity Failures** ✅ - Input validation, signed cookies
9. **Logging Failures** ✅ - Comprehensive logging without sensitive data
10. **SSRF** ✅ - No external requests, input validation

## 🚀 Installation

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0

### Setup

1. Install dependencies:

```bash
npm install
```

**Windows users:** The app uses `bcryptjs` (pure JavaScript) instead of `bcrypt` (native) to avoid compilation issues. No additional setup needed!

2. Copy environment file and configure:

```bash
cp .env.example .env
```

3. **IMPORTANT**: Edit `.env` file and change all default secrets:

   - `JWT_SECRET` - Use a strong random string (minimum 32 characters)
   - `COOKIE_SECRET` - Use a different strong random string (minimum 32 characters)
   - `ALLOWED_ORIGINS` - Set your production domain
   - Configure other settings as needed

4. Start the server:

**Development:**

```bash
npm run dev
```

**Production:**

```bash
NODE_ENV=production npm start
```

## 📖 API Endpoints

### Authentication

**Register User**

```
POST /api/auth/register
Content-Type: application/json

{
  "username": "testuser",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!"
}
```

**Login**

```
POST /api/auth/login
Content-Type: application/json

{
  "username": "testuser",
  "password": "SecurePass123!"
}
```

**Logout**

```
POST /api/auth/logout
Authorization: Bearer <token>
```

**Get Current User**

```
GET /api/auth/me
Authorization: Bearer <token>
```

### Notes (All require authentication)

**Get All Notes**

```
GET /api/notes
Authorization: Bearer <token>
```

**Get Single Note**

```
GET /api/notes/:id
Authorization: Bearer <token>
```

**Create Note**

```
POST /api/notes
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "My Note",
  "content": "Note content here"
}
```

**Update Note**

```
PUT /api/notes/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "Updated Title",
  "content": "Updated content"
}
```

**Delete Note**

```
DELETE /api/notes/:id
Authorization: Bearer <token>
```

## 🌐 Frontend

Access the web interface at: `http://localhost:3000`

The frontend includes:

- User registration and login forms
- Notes dashboard with list and editor
- Secure client-side validation
- XSS protection through HTML sanitization
- Responsive design

## 🔧 Configuration

### Environment Variables

| Variable                  | Description                   | Default                 |
| ------------------------- | ----------------------------- | ----------------------- |
| `NODE_ENV`                | Environment mode              | `development`           |
| `PORT`                    | Server port                   | `3000`                  |
| `HOST`                    | Server host                   | `localhost`             |
| `JWT_SECRET`              | JWT signing secret            | **MUST CHANGE**         |
| `JWT_EXPIRE`              | JWT expiration time           | `24h`                   |
| `COOKIE_SECRET`           | Cookie signing secret         | **MUST CHANGE**         |
| `ALLOWED_ORIGINS`         | CORS allowed origins          | `http://localhost:3000` |
| `BCRYPT_ROUNDS`           | Bcrypt hashing rounds         | `12`                    |
| `MAX_LOGIN_ATTEMPTS`      | Max failed login attempts     | `5`                     |
| `LOCKOUT_TIME`            | Account lockout duration (ms) | `900000` (15 min)       |
| `RATE_LIMIT_WINDOW_MS`    | Rate limit window             | `900000` (15 min)       |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window       | `100`                   |

## 🧪 Testing

Run security audit:

```bash
npm run security-audit
```

Run linting:

```bash
npm run lint
```

## 🚨 Production Deployment Checklist

- [ ] Change all default secrets in `.env`
- [ ] Set `NODE_ENV=production`
- [ ] Enable HTTPS/TLS
- [ ] Use a proper database (PostgreSQL, MongoDB, etc.)
- [ ] Implement Redis for rate limiting across instances
- [ ] Set up proper logging (Winston, Bunyan, etc.)
- [ ] Configure monitoring (PM2, New Relic, etc.)
- [ ] Set up automated backups
- [ ] Configure firewall rules
- [ ] Enable database encryption at rest
- [ ] Set up SSL/TLS certificates
- [ ] Configure reverse proxy (Nginx, Apache)
- [ ] Set proper CORS origins
- [ ] Review and adjust rate limits
- [ ] Set up error tracking (Sentry, etc.)
- [ ] Implement proper session storage
- [ ] Regular security audits
- [ ] Keep dependencies updated
- [ ] Set up CI/CD pipeline with security checks

## 📝 Known Limitations

1. **In-Memory Storage**: Current implementation uses in-memory storage for users and notes. In production, use a proper database with:

   - Encryption at rest
   - Regular backups
   - Replication for high availability
   - Proper indexing for performance

2. **Rate Limiting Storage**: Rate limiting uses in-memory storage. For multi-instance deployments, use Redis.

3. **File Uploads**: Not implemented. If needed, implement with:
   - File type validation
   - Size limits
   - Virus scanning
   - Secure storage (S3, etc.)

## 🆘 Support

For security issues, please follow responsible disclosure practices and report privately.

## 📄 License

MIT

## ⚖️ Disclaimer

This application has been built with security as a top priority. However, security is a continuous process. Regular audits, updates, and monitoring are essential for maintaining a secure production environment.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.**
