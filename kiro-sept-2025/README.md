# Secure Notes Application

A secure Node.js web application for managing personal notes with industry-standard security practices.

## Security Features

- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: User-specific note access control
- **Encryption**: AES-256-GCM encryption for sensitive data
- **Input Validation**: Comprehensive input validation and sanitization
- **Rate Limiting**: Protection against brute force attacks
- **Security Headers**: HTTPS-only, CSP, HSTS, and other security headers
- **Audit Logging**: Comprehensive security event logging

## Prerequisites

- Node.js 18+ LTS
- PostgreSQL 12+
- Redis 6+

## Setup

1. **Clone and install dependencies:**
   ```bash
   npm install
   ```

2. **Environment Configuration:**
   ```bash
   cp .env.example .env
   ```
   
   **IMPORTANT**: Generate secure keys for production:
   ```bash
   # Generate encryption key (256-bit)
   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
   
   # Generate JWT secrets
   node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"
   ```

3. **Database Setup:**
   - Create PostgreSQL database
   - Update DATABASE_URL in .env file
   - Ensure SSL is enabled for production

4. **Redis Setup:**
   - Install and start Redis server
   - Update REDIS_URL in .env file
   - Set Redis password for production

## Development

```bash
# Start development server
npm run dev

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Format code
npm run format

# Security audit
npm run security:audit
```

## Security Checklist

- [ ] Environment variables are properly configured
- [ ] Database connections use SSL
- [ ] Encryption keys are securely generated and stored
- [ ] JWT secrets are strong and unique
- [ ] Redis is password protected
- [ ] All dependencies are up to date
- [ ] Security linting passes
- [ ] Tests pass including security tests

## Production Deployment

1. Set NODE_ENV=production
2. Use strong, unique secrets for all keys
3. Enable database SSL
4. Configure proper CORS origins
5. Set up log monitoring and alerting
6. Regular security updates

## License

MIT