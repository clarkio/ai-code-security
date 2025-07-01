# Secure Notes Application

A production-ready, security-focused Node.js web application for creating, updating, and deleting personal notes.

## 🔒 Security Features

### Authentication & Authorization
- **JWT-based authentication** with access and refresh tokens
- **Bcrypt password hashing** with configurable rounds (default: 12)
- **Account lockout** after 5 failed login attempts (30-minute cooldown)
- **Session management** with secure, httpOnly, sameSite cookies
- **Token refresh mechanism** for seamless user experience

### Input Validation & Sanitization
- **Joi validation schemas** for all user inputs
- **XSS protection** using the xss library on both client and server
- **SQL injection prevention** through prepared statements (better-sqlite3)
- **Request body size limits** (10kb) to prevent DoS attacks

### Security Headers & Middleware
- **Helmet.js** for comprehensive security headers:
  - Content Security Policy (CSP)
  - HSTS with preload
  - X-Frame-Options
  - X-Content-Type-Options
  - And more...
- **CORS configuration** with whitelist
- **Rate limiting** on all API endpoints
- **Stricter rate limiting** on authentication endpoints
- **HTTP Parameter Pollution (HPP) protection**

### Database Security
- **Prepared statements** for all database queries
- **Foreign key constraints** for data integrity
- **Soft deletes** for notes (data recovery possible)
- **Audit logging** for all sensitive operations
- **Automatic cleanup** of expired tokens

### Additional Security Measures
- **CSRF protection** ready (tokens generated)
- **Secure error handling** (no stack traces in production)
- **Request logging** with IP tracking
- **Graceful shutdown** handling
- **Environment variable validation**
- **Secure random token generation**
- **Constant-time string comparison** for tokens

## 📋 Prerequisites

- Node.js >= 18.0.0
- npm or yarn
- SQLite3 (included via better-sqlite3)

## 🚀 Installation

1. Clone the repository:
```bash
cd cursor-agent-claude-4-opus
```

2. Install dependencies:
```bash
npm install
```

3. Create environment file:
```bash
cp .env.example .env
```

4. **IMPORTANT**: Update the `.env` file with secure values:
```env
JWT_SECRET=<generate-a-long-random-string>
SESSION_SECRET=<generate-another-long-random-string>
```

Generate secure secrets using:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## 🏃 Running the Application

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
NODE_ENV=production npm start
```

The application will be available at `http://localhost:3000`

## 🌐 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout current session
- `POST /api/auth/logout-all` - Logout all sessions
- `GET /api/auth/me` - Get current user info

### Notes
- `GET /api/notes` - Get all notes (paginated)
- `GET /api/notes/:id` - Get specific note
- `POST /api/notes` - Create new note
- `PUT /api/notes/:id` - Update note
- `DELETE /api/notes/:id` - Delete note (soft delete)
- `GET /api/notes/search?q=query` - Search notes

## 🔧 Configuration

All configuration is done through environment variables. See `.env.example` for available options.

### Key Configuration Options:
- `NODE_ENV` - Set to 'production' for production deployment
- `PORT` - Server port (default: 3000)
- `BCRYPT_ROUNDS` - Password hashing rounds (default: 12)
- `RATE_LIMIT_WINDOW_MS` - Rate limit window in milliseconds
- `RATE_LIMIT_MAX_REQUESTS` - Maximum requests per window
- `DATABASE_PATH` - SQLite database file path

## 🚢 Production Deployment

### Pre-deployment Checklist

1. **Environment Variables**
   - [ ] Generate strong JWT_SECRET (min 64 characters)
   - [ ] Generate strong SESSION_SECRET (min 64 characters)
   - [ ] Set NODE_ENV=production
   - [ ] Update ALLOWED_ORIGINS for your domain

2. **HTTPS Setup**
   - [ ] Use a reverse proxy (Nginx/Apache) with SSL/TLS
   - [ ] Enable HSTS in production
   - [ ] Obtain SSL certificate (Let's Encrypt recommended)

3. **Database**
   - [ ] Backup database regularly
   - [ ] Set appropriate file permissions (600)
   - [ ] Store database outside web root

4. **Server Security**
   - [ ] Keep Node.js updated
   - [ ] Run application as non-root user
   - [ ] Use process manager (PM2, systemd)
   - [ ] Configure firewall rules
   - [ ] Enable automatic security updates

### Deployment with PM2

1. Install PM2:
```bash
npm install -g pm2
```

2. Start application:
```bash
pm2 start server.js --name secure-notes
```

3. Save PM2 configuration:
```bash
pm2 save
pm2 startup
```

### Nginx Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

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

## 🔍 Security Monitoring

1. **Check logs regularly**:
   - Application logs: `./logs/app.log`
   - Error logs: `./logs/error.log`
   - Audit logs in database

2. **Monitor for**:
   - Failed login attempts
   - Unusual API usage patterns
   - Error spikes
   - Database query performance

3. **Security updates**:
```bash
npm audit
npm audit fix
```

## 🧪 Testing

Run security audit:
```bash
npm audit
```

## 📝 License

MIT License - See LICENSE file for details

## ⚠️ Security Disclosure

If you discover a security vulnerability, please email security@your-domain.com. Do not create public issues for security vulnerabilities.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

All contributions must maintain or improve the security posture of the application.