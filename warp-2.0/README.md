# 🔒 Secure Notes Application

A production-ready, security-focused Node.js web application for creating, updating, and deleting personal notes. This application implements comprehensive security measures to protect against common web vulnerabilities.

## 🛡️ Security Features

### Authentication & Authorization
- **JWT-based authentication** with secure token generation
- **Password hashing** using bcrypt with 12 salt rounds
- **Account lockout** after 5 failed login attempts (15-minute lockout)
- **Token blacklisting** for secure logout functionality
- **Strong password requirements** (uppercase, lowercase, numbers, special characters)

### Input Validation & Sanitization
- **Comprehensive input validation** using express-validator
- **XSS protection** with content sanitization
- **SQL injection prevention** via parameterized queries
- **Input length limits** to prevent buffer overflow attacks
- **Character encoding validation**

### Rate Limiting & DDoS Protection
- **Global rate limiting** (100 requests per 15 minutes by default)
- **Authentication rate limiting** (5 attempts per 15 minutes)
- **Configurable rate limits** via environment variables

### Security Headers & CORS
- **Helmet.js** for comprehensive security headers
- **CORS protection** with configurable allowed origins
- **Content Security Policy** to prevent XSS attacks
- **HSTS headers** for HTTPS enforcement
- **X-Frame-Options** to prevent clickjacking

### Database Security
- **Foreign key constraints** for data integrity
- **Database-level validation** with CHECK constraints
- **Automatic session cleanup** for expired tokens
- **SQLite with proper file permissions**

### Production Security
- **HTTPS/TLS support** with SSL certificate configuration
- **Environment-based configuration** for secure secrets management
- **Graceful shutdown** handling for production deployments
- **Comprehensive error handling** without information leakage

## 📋 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user (requires authentication)

### Notes Management
- `GET /api/notes` - Get all notes for authenticated user
- `GET /api/notes/:id` - Get specific note
- `POST /api/notes` - Create new note
- `PUT /api/notes/:id` - Update existing note
- `DELETE /api/notes/:id` - Delete note

### System
- `GET /health` - Health check endpoint

## 🚀 Installation & Setup

### Prerequisites
- Node.js 18+ (specified in package.json engines)
- npm or yarn package manager

### Development Setup

1. **Clone and navigate to the project:**
   ```bash
   cd warp-2.0
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # CRITICAL: Generate secure secrets for production
   node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
   node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
   ```

4. **Start the development server:**
   ```bash
   npm run dev
   ```

5. **Access the application:**
   - Open your browser to `http://localhost:3000`
   - The database will be automatically created on first run

### Production Deployment

1. **Environment Configuration:**
   ```bash
   # Set production environment
   NODE_ENV=production
   
   # Generate cryptographically secure secrets
   JWT_SECRET=<64-character-hex-string>
   SESSION_SECRET=<64-character-hex-string>
   
   # Configure SSL certificates
   SSL_CERT_PATH=/path/to/your/certificate.crt
   SSL_KEY_PATH=/path/to/your/private.key
   
   # Set your domain for CORS
   ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
   ```

2. **SSL Certificate Setup:**
   ```bash
   # For Let's Encrypt certificates
   SSL_CERT_PATH=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
   SSL_KEY_PATH=/etc/letsencrypt/live/yourdomain.com/privkey.pem
   ```

3. **Start production server:**
   ```bash
   npm start
   ```

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Server port | 3000 | No |
| `NODE_ENV` | Environment mode | development | No |
| `JWT_SECRET` | JWT signing secret | - | **Yes** |
| `SESSION_SECRET` | Session secret | - | **Yes** |
| `DB_PATH` | Database file path | ./data/notes.db | No |
| `RATE_LIMIT_WINDOW_MS` | Rate limit window | 900000 (15 min) | No |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window | 100 | No |
| `ALLOWED_ORIGINS` | CORS allowed origins | localhost:3000 | No |
| `SSL_CERT_PATH` | SSL certificate path | - | Production only |
| `SSL_KEY_PATH` | SSL private key path | - | Production only |

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&*(),.?":{}|<>)

### Input Limits
- Username: 3-50 characters (alphanumeric, underscore, hyphen only)
- Email: Standard email format, max 100 characters
- Note title: 1-200 characters
- Note content: 1-10,000 characters

## 🧪 Testing

### Run Security Audit
```bash
npm run security-audit
```

### Manual Security Testing

1. **Test rate limiting:**
   ```bash
   # Make multiple rapid requests to trigger rate limiting
   for i in {1..10}; do curl -X POST http://localhost:3000/api/auth/login; done
   ```

2. **Test input validation:**
   ```bash
   # Test XSS prevention
   curl -X POST http://localhost:3000/api/auth/register \
        -H "Content-Type: application/json" \
        -d '{"username":"<script>alert(\"xss\")</script>","email":"test@test.com","password":"Test123!"}'
   ```

3. **Test SQL injection prevention:**
   ```bash
   # This should be safely handled
   curl -X POST http://localhost:3000/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"usernameOrEmail":"admin'\'' OR 1=1--","password":"anything"}'
   ```

## 🚨 Security Checklist for Production

### Before Deployment
- [ ] Change all default secrets in `.env`
- [ ] Set `NODE_ENV=production`
- [ ] Configure SSL certificates
- [ ] Set proper CORS origins
- [ ] Review and adjust rate limits
- [ ] Ensure database file has proper permissions
- [ ] Run security audit: `npm run security-audit`
- [ ] Test all authentication flows
- [ ] Verify input validation on all endpoints

### Infrastructure Security
- [ ] Use HTTPS/TLS in production
- [ ] Configure reverse proxy (nginx/Apache) with security headers
- [ ] Set up database backups
- [ ] Configure log monitoring
- [ ] Implement network-level rate limiting
- [ ] Use a Web Application Firewall (WAF)
- [ ] Regular security updates for dependencies

### Monitoring & Maintenance
- [ ] Monitor failed login attempts
- [ ] Set up alerts for rate limit triggers
- [ ] Regular dependency updates
- [ ] Periodic security audits
- [ ] Log analysis for suspicious activity

## 🐛 Common Issues & Solutions

### Issue: "JWT_SECRET must be at least 32 characters long"
**Solution:** Generate a proper secret:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Issue: CORS errors in production
**Solution:** Update `ALLOWED_ORIGINS` in `.env` to include your domain:
```
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### Issue: Database permission errors
**Solution:** Ensure the application has write access to the database directory:
```bash
chmod 755 data/
chmod 644 data/notes.db
```

## 📞 Support

For security-related issues or questions about production deployment, please:

1. Review this documentation thoroughly
2. Check the security checklist
3. Verify all environment variables are properly set
4. Test in a staging environment before production deployment

## ⚠️ Security Disclaimer

This application implements industry-standard security practices, but security is an ongoing process. Always:

- Keep dependencies updated
- Monitor for security advisories
- Conduct regular security audits
- Follow the principle of least privilege
- Implement additional layers of security as needed for your specific use case

**Remember: Your job depends on the security of this application. Take every precaution seriously!**
