# Security Checklist for Production Deployment

## ⚡ CRITICAL - Must Complete Before Production

### 🔑 Secrets Management
- [ ] Generated new SESSION_SECRET using cryptographically secure random generator
- [ ] Generated new JWT_SECRET using cryptographically secure random generator  
- [ ] All default secrets in .env have been replaced with strong, unique values
- [ ] .env file is NOT committed to version control
- [ ] Secrets are stored securely in production (environment variables, secret manager)

### 🔒 HTTPS Configuration
- [ ] Application is deployed behind HTTPS
- [ ] SESSION_SECURE is set to `true` in production
- [ ] HSTS header is enabled with appropriate max-age
- [ ] SSL certificate is valid and from trusted CA
- [ ] Redirect HTTP to HTTPS is configured

### 🛡️ Environment Configuration
- [ ] NODE_ENV is set to `production`
- [ ] Debug mode is disabled
- [ ] Error messages don't expose sensitive information
- [ ] ALLOWED_ORIGINS is set to specific domains (not wildcards)
- [ ] ENABLE_TRUST_PROXY is configured correctly for your setup

### 📊 Database Security
- [ ] Production database has strong passwords
- [ ] Database connections use SSL/TLS
- [ ] Database user has minimum required permissions
- [ ] Regular automated backups are configured
- [ ] Database is not accessible from public internet

## ✅ Security Features Verification

### Authentication & Authorization
- [ ] Password requirements are enforced (min 8 chars, complexity)
- [ ] Account lockout works after 5 failed attempts
- [ ] JWT tokens expire appropriately
- [ ] Sessions timeout after inactivity
- [ ] Users cannot access other users' private notes

### Input Validation & Sanitization  
- [ ] All inputs are validated on the server side
- [ ] XSS protection is working (test with `<script>alert('xss')</script>`)
- [ ] SQL injection is prevented (test with `'; DROP TABLE users; --`)
- [ ] File upload size limits are enforced
- [ ] Request payload size limits are enforced

### Security Headers
- [ ] Helmet.js headers are properly set
- [ ] Content Security Policy is configured
- [ ] X-Frame-Options prevents clickjacking
- [ ] X-Content-Type-Options prevents MIME sniffing
- [ ] Referrer-Policy is configured

### Rate Limiting
- [ ] General rate limiting is active
- [ ] Authentication endpoints have stricter limits
- [ ] Rate limit headers are sent to clients
- [ ] Rate limiting persists across server restarts

### CSRF Protection
- [ ] CSRF tokens are generated for each session
- [ ] State-changing operations require valid CSRF token
- [ ] CSRF token is included in all forms/AJAX requests
- [ ] Token validation is working correctly

## 🚀 Deployment Security

### Infrastructure
- [ ] Server OS and software are up to date
- [ ] Firewall is configured (only necessary ports open)
- [ ] SSH uses key-based authentication only
- [ ] Fail2ban or similar is configured for SSH
- [ ] Server logs are monitored

### Application Security
- [ ] Application runs as non-root user
- [ ] File permissions are restrictive (no world-writable)
- [ ] Sensitive directories are protected
- [ ] Static file serving has proper restrictions
- [ ] Directory listing is disabled

### Monitoring & Logging
- [ ] Application logs are stored securely
- [ ] Security events are logged (failed logins, etc.)
- [ ] Log rotation is configured
- [ ] Monitoring alerts are set up for:
  - [ ] Multiple failed login attempts
  - [ ] Rate limit violations
  - [ ] Application errors
  - [ ] Unusual traffic patterns

## 🔍 Security Testing

### Manual Testing
- [ ] Tested registration with weak passwords (should fail)
- [ ] Tested SQL injection attempts
- [ ] Tested XSS attempts
- [ ] Tested accessing other users' data
- [ ] Tested CSRF protection
- [ ] Tested rate limiting

### Automated Scanning
- [ ] Ran npm audit and fixed vulnerabilities
- [ ] Performed security headers scan
- [ ] Ran OWASP ZAP or similar security scanner
- [ ] Checked SSL configuration with SSL Labs
- [ ] Performed penetration testing (if applicable)

## 📝 Documentation & Procedures

### Security Documentation
- [ ] Incident response plan is documented
- [ ] Security contacts are defined
- [ ] Data breach procedure is documented
- [ ] Backup restoration procedure is tested

### Maintenance
- [ ] Dependency update schedule is defined
- [ ] Security patch process is documented
- [ ] Regular security review schedule is set
- [ ] Team is trained on security best practices

## 🚨 Final Checks

- [ ] All items above are checked and verified
- [ ] Security review has been performed by another team member
- [ ] Penetration test has been conducted (for critical applications)
- [ ] Legal/compliance requirements are met (GDPR, etc.)
- [ ] Disaster recovery plan is in place and tested

---

**Remember**: Security is an ongoing process. This checklist should be reviewed:
- Before each deployment
- After any significant changes
- At least quarterly
- Whenever new vulnerabilities are discovered

**Never compromise on security. Your job depends on it!**