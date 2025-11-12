# Secure Notes App

A production-ready, security-focused Node.js web application for creating, updating, and deleting notes. Built with multiple layers of security protection to ensure safe deployment in production environments.

## 🛡️ Security Features

### Core Security Implementation
- **Helmet.js**: Sets security-related HTTP headers
- **CORS Protection**: Configurable cross-origin resource sharing
- **Rate Limiting**: Prevents brute force attacks
- **CSRF Protection**: Cross-site request forgery tokens
- **Input Validation**: Comprehensive validation using Joi and express-validator
- **Input Sanitization**: XSS prevention with DOMPurify
- **Content Security Policy**: Strict CSP headers
- **Security Logging**: Comprehensive security event monitoring

### Security Headers
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security` (HTTPS enforcement)
- `Referrer-Policy: strict-origin-when-cross-origin`

### Input Protection
- HTML tag prevention in titles
- SQL injection pattern detection
- Directory traversal protection
- JavaScript protocol filtering
- Maximum length validation
- Character restrictions for tags

## 🚀 Quick Start

### Prerequisites
- Node.js >= 18.0.0
- npm >= 8.0.0

### Installation

1. **Clone and install dependencies**
   ```bash
   git clone <repository-url>
   cd secure-notes-app
   npm install
   ```

2. **Environment configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your secure configuration
   ```

3. **Security setup**
   ```bash
   # Generate secure secrets (REQUIRED FOR PRODUCTION)
   npm run security-check
   ```

4. **Start the application**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

## 📁 Project Structure

```
secure-notes-app/
├── middleware/           # Security and validation middleware
│   ├── errorHandler.js   # Global error handler
│   ├── securityLogger.js # Security event logging
│   ├── validation.js     # Input validation schemas
│   └── sanitization.js   # Input sanitization functions
├── models/              # Data models
│   └── Note.js          # Note data management
├── routes/              # API routes
│   └── notes.js         # Notes CRUD operations
├── public/              # Frontend assets
│   ├── index.html       # Main application page
│   └── app.js           # Frontend JavaScript
├── scripts/             # Utility scripts
│   └── security-monitor.js # Security monitoring
├── tests/               # Test suite
│   ├── notes.test.js    # API tests
│   └── setup.js         # Test configuration
├── utils/               # Utility functions
│   └── logger.js        # Logging configuration
├── data/                # Data storage (auto-created)
├── logs/                # Application logs (auto-created)
├── server.js            # Main application server
├── package.json         # Dependencies and scripts
├── .env.example         # Environment template
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```env
# Environment Configuration
NODE_ENV=production
PORT=3000

# Security Configuration (CHANGE THESE IN PRODUCTION)
SESSION_SECRET=your-super-secure-random-secret-key-here
JWT_SECRET=your-jwt-secret-key-here

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com

# Logging
LOG_LEVEL=info
LOG_FILE=logs/app.log
```

### Security Configuration

**CRITICAL**: Before deploying to production, you MUST:

1. **Generate secure secrets**:
   ```bash
   # Use a cryptographically secure random generator
   node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"
   node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"
   ```

2. **Configure allowed origins**:
   ```env
   ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
   ```

3. **Set production environment**:
   ```env
   NODE_ENV=production
   ```

## 🧪 Testing

### Run Test Suite
```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage report
npm run test:coverage
```

### Security Testing
```bash
# Run comprehensive security check
npm run security-check

# Run security monitoring
npm run security-monitor
```

## 📊 API Endpoints

### Notes API
- `GET /api/notes` - Get all notes
- `GET /api/notes/:id` - Get specific note
- `POST /api/notes` - Create new note
- `PUT /api/notes/:id` - Update note
- `DELETE /api/notes/:id` - Delete note
- `GET /api/notes/tags` - Get all tags

### Security Endpoints
- `GET /api/csrf-token` - Get CSRF token
- `GET /health` - Health check

## 🛠️ Development

### Code Quality
```bash
# Run linting
npm run lint

# Fix linting issues
npm run lint:fix
```

### Security Monitoring
The application includes automated security monitoring:

1. **Real-time threat detection**: Logs suspicious patterns
2. **File integrity monitoring**: Detects unauthorized file changes
3. **Rate limiting**: Prevents abuse
4. **Input validation**: Blocks malicious inputs

## 🚀 Deployment

### Production Deployment Checklist

1. **Environment Setup**
   - [ ] Set `NODE_ENV=production`
   - [ ] Generate secure secrets
   - [ ] Configure allowed origins
   - [ ] Set appropriate rate limits

2. **Security Verification**
   - [ ] Run `npm audit` for vulnerabilities
   - [ ] Run `npm run security-check`
   - [ ] Verify HTTPS is enabled
   - [ ] Check security headers

3. **Server Configuration**
   - [ ] Use reverse proxy (nginx/Apache)
   - [ ] Enable HTTPS with valid certificates
   - [ ] Configure firewall rules
   - [ ] Set up monitoring and alerts

4. **Database/Storage**
   - [ ] Secure file permissions
   - [ ] Set up backups
   - [ ] Configure access controls

### Docker Deployment (Optional)

Create a `Dockerfile`:
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
USER node
CMD ["npm", "start"]
```

## 🔒 Security Best Practices

### What This App Implements
- ✅ Input validation and sanitization
- ✅ XSS protection
- ✅ CSRF protection
- ✅ SQL injection prevention
- ✅ Rate limiting
- ✅ Security headers
- ✅ Error handling
- ✅ Logging and monitoring
- ✅ File integrity checks

### Additional Recommendations
1. **Use HTTPS**: Always deploy behind SSL/TLS
2. **Regular Updates**: Keep dependencies updated
3. **Monitoring**: Set up log monitoring and alerts
4. **Backups**: Regular data backups
5. **Access Control**: Implement authentication if needed
6. **Network Security**: Use firewalls and VPNs

## 📝 License

MIT License - see LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run security checks: `npm run security-check`
5. Submit a pull request

## 📞 Support

For security issues, please report privately rather than creating a public issue.
