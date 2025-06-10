# Secure Notes Application

A production-ready, secure Node.js notes application with comprehensive security features.

## 🔒 Security Features

This application implements multiple layers of security to protect against common web vulnerabilities:

### Authentication & Authorization

- **JWT Tokens**: Secure token-based authentication
- **Session Management**: Secure session handling with SQLite store
- **Password Security**: Bcrypt hashing with configurable rounds
- **Account Security**: Failed login attempt tracking and account locking

### Input Validation & Sanitization

- **Server-side Validation**: Express-validator for comprehensive input validation
- **XSS Protection**: Input sanitization to prevent cross-site scripting
- **SQL Injection Prevention**: Parameterized queries with SQLite3
- **Content Length Limits**: Prevent payload-based attacks

### Rate Limiting & DoS Protection

- **General Rate Limiting**: 100 requests per 15 minutes per IP
- **Auth Rate Limiting**: 5 authentication attempts per 15 minutes per IP
- **Slow Down Middleware**: Progressive delays for suspicious activity
- **Brute Force Protection**: Exponential backoff for repeated failures

### Security Headers & CORS

- **Helmet.js**: Comprehensive security headers
- **Content Security Policy**: Strict CSP to prevent XSS
- **CORS Configuration**: Restricted cross-origin access
- **CSRF Protection**: Token-based CSRF prevention

### Data Protection

- **Environment Variables**: Sensitive data in environment files
- **Secure Cookies**: HttpOnly, Secure, SameSite cookie attributes
- **Database Security**: Foreign key constraints and indexes
- **Input Sanitization**: XSS library for output sanitization

## 🚀 Quick Start

### Prerequisites

- Node.js 18.0.0 or higher
- npm or yarn package manager

### Installation

1. **Clone and navigate to the project**:

   ```bash
   cd claude-sonnet-4
   ```

2. **Install dependencies**:

   ```bash
   npm install
   ```

3. **Configure environment variables**:

   ```bash
   cp .env.example .env
   ```

   **⚠️ CRITICAL: Update the following in your .env file for production:**

   ```
   NODE_ENV=production
   JWT_SECRET=your-256-bit-random-secret-key-here
   SESSION_SECRET=your-256-bit-random-session-secret-here
   CORS_ORIGIN=https://yourdomain.com
   ```

4. **Start the application**:

   ```bash
   # Development mode
   npm run dev

   # Production mode
   npm start
   ```

5. **Access the application**:
   Open your browser to `http://localhost:3000`

## 🔧 Configuration

### Environment Variables

| Variable         | Description             | Default                 | Security Level |
| ---------------- | ----------------------- | ----------------------- | -------------- |
| `NODE_ENV`       | Environment mode        | `development`           | High           |
| `PORT`           | Server port             | `3000`                  | Low            |
| `JWT_SECRET`     | JWT signing secret      | -                       | **CRITICAL**   |
| `SESSION_SECRET` | Session signing secret  | -                       | **CRITICAL**   |
| `DB_PATH`        | Database file path      | `./data/notes.db`       | Medium         |
| `BCRYPT_ROUNDS`  | Password hashing rounds | `12`                    | High           |
| `JWT_EXPIRES_IN` | Token expiration time   | `1h`                    | Medium         |
| `CORS_ORIGIN`    | Allowed CORS origin     | `http://localhost:3000` | High           |

### Security Recommendations

#### For Production Deployment:

1. **Generate Strong Secrets**:

   ```bash
   # Generate 256-bit random keys
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

2. **Use HTTPS**:

   - Always use HTTPS in production
   - Update `CORS_ORIGIN` to your HTTPS domain
   - Set secure cookie settings

3. **Database Security**:

   - Use proper file permissions for database files
   - Regular database backups
   - Consider encryption at rest

4. **Server Hardening**:

   - Use a reverse proxy (nginx)
   - Implement IP whitelisting if needed
   - Regular security updates

5. **Monitoring**:
   - Implement logging and monitoring
   - Set up alerts for suspicious activity
   - Regular security audits

## 📁 Project Structure

```
claude-sonnet-4/
├── server.js              # Main application server
├── database.js            # Database configuration and setup
├── auth.js                # Authentication middleware and controllers
├── notes.js               # Notes controller and business logic
├── package.json           # Dependencies and scripts
├── .env                   # Environment variables (create from .env.example)
├── .env.example           # Environment variables template
├── public/                # Static frontend files
│   ├── index.html         # Main HTML file
│   ├── style.css          # Application styles
│   └── app.js             # Frontend JavaScript
└── data/                  # Database and session files (auto-created)
    ├── notes.db           # SQLite database
    ├── sessions.db        # Session store
    └── brute.db           # Brute force protection store
```

## 🛡️ Security Testing

Run security audits regularly:

```bash
# Check for vulnerable dependencies
npm audit

# Fix automatically fixable vulnerabilities
npm audit fix

# Check for security issues in code
npm run lint
```

## 🐛 Troubleshooting

### Common Issues:

1. **CSRF Token Errors**:

   - Ensure the frontend is getting CSRF tokens
   - Check CORS configuration

2. **Database Errors**:

   - Verify the `data/` directory has write permissions
   - Check if SQLite3 is properly installed

3. **Authentication Issues**:

   - Verify JWT_SECRET is set
   - Check token expiration settings

4. **Rate Limiting**:
   - If locked out, wait for the rate limit window to reset
   - Check IP address configuration in development

## 📝 API Endpoints

### Authentication

- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/csrf-token` - Get CSRF token

### Notes

- `GET /api/notes` - Get all user notes
- `GET /api/notes/:id` - Get specific note
- `POST /api/notes` - Create new note
- `PUT /api/notes/:id` - Update note
- `DELETE /api/notes/:id` - Delete note

### Utility

- `GET /health` - Health check endpoint

## 🔐 Security Checklist

Before deploying to production, ensure:

- [ ] Strong JWT and session secrets are set
- [ ] HTTPS is enabled
- [ ] CORS is properly configured
- [ ] Database files have appropriate permissions
- [ ] Environment variables are secure
- [ ] Dependencies are up to date
- [ ] Rate limiting is appropriately configured
- [ ] Monitoring and logging are set up
- [ ] Regular security audits are scheduled

## ⚡ Performance

The application is optimized for performance with:

- Database indexing for quick queries
- Efficient session storage
- Minimal dependencies
- Frontend asset optimization
- Rate limiting to prevent abuse

## 🤝 Contributing

1. Security issues should be reported privately
2. Follow security best practices in any contributions
3. Test thoroughly before submitting changes
4. Update documentation for security-related changes

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**⚠️ SECURITY WARNING**: This application contains security-critical code. Always review and test thoroughly before deploying to production. Ensure all environment variables are properly configured and secrets are kept secure.
