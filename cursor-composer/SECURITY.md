# Security Documentation

This document outlines all security measures implemented in the Secure Notes Application.

## Authentication & Authorization

### Password Security
- **Bcrypt hashing**: All passwords are hashed using bcrypt with 12 salt rounds
- **Password requirements**: Minimum 8 characters, must contain uppercase, lowercase, and number
- **No password storage**: Passwords are never stored in plaintext

### JWT Tokens
- **Token expiration**: 24 hours
- **Secure storage**: Tokens stored in localStorage (consider httpOnly cookies for enhanced security)
- **Token verification**: Every request verifies token validity and user existence
- **Secret key**: JWT_SECRET must be a strong random string (use `openssl rand -base64 32`)

## SQL Injection Prevention

✅ **100% Protected** - All database queries use parameterized queries (prepared statements)
- No string concatenation in SQL queries
- All user inputs passed as parameters ($1, $2, etc.)
- Example: `SELECT * FROM users WHERE email = $1` instead of `SELECT * FROM users WHERE email = '${email}'`

## XSS (Cross-Site Scripting) Prevention

- **Input sanitization**: All user inputs are validated and sanitized using express-validator
- **HTML escaping**: Frontend uses textContent instead of innerHTML
- **Content Security Policy**: Helmet.js CSP headers prevent inline script execution
- **Input validation**: Length limits and format validation on all inputs

## CSRF (Cross-Site Request Forgery) Protection

- **SameSite cookies**: Set to 'strict' to prevent cross-site cookie sending
- **Session-based tokens**: Session storage for CSRF tokens (infrastructure ready)
- **CORS configuration**: Properly configured to allow only trusted origins

## Security Headers

All security headers are configured via Helmet.js:
- **Content-Security-Policy**: Restricts resource loading
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **Strict-Transport-Security**: HTTPS enforcement (when HTTPS is configured)
- **X-XSS-Protection**: Additional XSS protection

## Rate Limiting

- **General API**: 100 requests per 15 minutes per IP
- **Authentication endpoints**: 5 attempts per 15 minutes per IP
- **Purpose**: Prevents brute force attacks and DoS

## Input Validation

- **express-validator**: All inputs validated and sanitized
- **Email normalization**: Email addresses normalized before storage
- **Length limits**: 
  - Username: 3-50 characters
  - Title: 1-255 characters
  - Content: 1-10,000 characters
- **Format validation**: Username must match regex pattern

## Error Handling

- **No information leakage**: Error messages don't expose internal details
- **Generic errors**: Production mode shows generic error messages
- **Proper logging**: Errors logged server-side without exposing to client

## Session Security

- **httpOnly cookies**: Prevents JavaScript access to cookies
- **Secure flag**: Enabled in production (HTTPS only)
- **SameSite**: Set to 'strict' for CSRF protection
- **Session expiration**: 24 hours

## Database Security

- **Connection pooling**: Prevents connection exhaustion
- **Connection timeouts**: 2 second timeout for new connections
- **SSL/TLS**: Enabled in production
- **Parameterized queries**: All queries use prepared statements

## Additional Security Measures

- **HTTP Parameter Pollution prevention**: HPP middleware prevents parameter pollution attacks
- **Payload size limits**: 10kb limit on request bodies
- **CORS**: Properly configured for production
- **Environment variables**: Sensitive data stored in environment variables, not code

## Production Deployment Security Checklist

- [ ] Change `JWT_SECRET` to strong random value
- [ ] Change `SESSION_SECRET` to strong random value  
- [ ] Set `NODE_ENV=production`
- [ ] Use HTTPS (configure SSL/TLS certificates)
- [ ] Use production-grade PostgreSQL database
- [ ] Configure firewall rules
- [ ] Set up reverse proxy (nginx/Apache) with proper security headers
- [ ] Set up monitoring and alerting
- [ ] Regular dependency updates (`npm audit`)
- [ ] Database backups configured
- [ ] Review CORS settings for production domain
- [ ] Set up rate limiting at infrastructure level
- [ ] Consider implementing httpOnly cookies for JWT storage
- [ ] Enable database connection encryption
- [ ] Set up log aggregation and monitoring
- [ ] Configure automatic security updates

## Known Security Considerations

1. **JWT Storage**: Currently stored in localStorage. Consider httpOnly cookies for enhanced XSS protection
2. **Rate Limiting**: Currently IP-based. Consider user-based rate limiting for authenticated users
3. **Password Reset**: Not implemented - add secure password reset flow for production
4. **Email Verification**: Not implemented - add email verification for new registrations
5. **Two-Factor Authentication**: Not implemented - consider for high-security deployments
6. **Audit Logging**: Consider adding audit logs for sensitive operations

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly. Do not create public GitHub issues for security vulnerabilities.

