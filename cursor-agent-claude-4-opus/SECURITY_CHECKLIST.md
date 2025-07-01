# Production Security Checklist

## 🔐 Pre-Deployment Security Checklist

### Environment & Configuration
- [ ] **Generate cryptographically secure secrets**
  ```bash
  # Generate JWT secret (minimum 64 characters)
  node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
  
  # Generate session secret (minimum 64 characters)
  node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
  ```
- [ ] Set `NODE_ENV=production`
- [ ] Update `ALLOWED_ORIGINS` to include only your production domain(s)
- [ ] Ensure `.env` file is NOT committed to version control
- [ ] Set appropriate `BCRYPT_ROUNDS` (12-14 for production)
- [ ] Configure proper rate limiting values based on expected traffic

### Database Security
- [ ] Move database file outside of web-accessible directory
- [ ] Set file permissions to 600 (read/write for owner only)
  ```bash
  chmod 600 /path/to/notes.db
  ```
- [ ] Set up automated database backups
- [ ] Test database restore procedure
- [ ] Enable database encryption at rest (if supported by hosting)

### Application Security
- [ ] Run `npm audit` and fix all vulnerabilities
  ```bash
  npm audit
  npm audit fix
  ```
- [ ] Remove all development dependencies in production
  ```bash
  npm prune --production
  ```
- [ ] Verify all input validation is working correctly
- [ ] Test rate limiting on authentication endpoints
- [ ] Verify account lockout mechanism works
- [ ] Test XSS protection with various payloads
- [ ] Verify SQL injection protection with malicious inputs
- [ ] Check that error messages don't leak sensitive information

### Server Configuration
- [ ] **Configure HTTPS/TLS**
  - [ ] Obtain SSL certificate (Let's Encrypt recommended)
  - [ ] Configure strong cipher suites
  - [ ] Enable TLS 1.2 minimum
  - [ ] Test SSL configuration with SSL Labs
- [ ] **Set up reverse proxy (Nginx/Apache)**
  - [ ] Hide Express server signature
  - [ ] Add security headers at proxy level
  - [ ] Configure request size limits
  - [ ] Enable gzip compression
- [ ] **Configure firewall**
  - [ ] Allow only necessary ports (80, 443)
  - [ ] Restrict SSH access to specific IPs
  - [ ] Block unused ports
- [ ] **System hardening**
  - [ ] Create dedicated user for application (non-root)
  - [ ] Disable root SSH login
  - [ ] Set up fail2ban for SSH protection
  - [ ] Enable automatic security updates

### Monitoring & Logging
- [ ] **Set up log rotation**
  ```bash
  # Example logrotate configuration
  /path/to/logs/*.log {
      daily
      rotate 14
      compress
      delaycompress
      notifempty
      create 0640 appuser appgroup
  }
  ```
- [ ] **Configure monitoring**
  - [ ] Set up uptime monitoring
  - [ ] Configure error alerting
  - [ ] Monitor disk space for database growth
  - [ ] Set up CPU/memory alerts
- [ ] **Security monitoring**
  - [ ] Monitor failed login attempts
  - [ ] Alert on multiple account lockouts
  - [ ] Track unusual API usage patterns
  - [ ] Monitor for large numbers of 4xx/5xx errors

### Deployment Process
- [ ] **Use process manager (PM2)**
  ```bash
  pm2 start server.js --name secure-notes -i max
  pm2 save
  pm2 startup
  ```
- [ ] **Set resource limits**
  ```bash
  # In ecosystem.config.js
  module.exports = {
    apps: [{
      name: 'secure-notes',
      script: 'server.js',
      instances: 'max',
      max_memory_restart: '1G',
      error_file: './logs/pm2-error.log',
      out_file: './logs/pm2-out.log',
      log_file: './logs/pm2-combined.log',
      time: true
    }]
  }
  ```
- [ ] Configure automatic restarts on failure
- [ ] Set up graceful reload for zero-downtime deployments

### Testing
- [ ] **Security testing**
  - [ ] Run OWASP ZAP or similar security scanner
  - [ ] Test with Burp Suite for vulnerabilities
  - [ ] Perform penetration testing
  - [ ] Test rate limiting under load
- [ ] **Load testing**
  - [ ] Test application under expected load
  - [ ] Verify rate limiting doesn't affect legitimate users
  - [ ] Check database performance under load
- [ ] **Backup testing**
  - [ ] Test full backup and restore procedure
  - [ ] Verify data integrity after restore
  - [ ] Document recovery time objective (RTO)

### Documentation
- [ ] Document all security configurations
- [ ] Create incident response plan
- [ ] Document backup and restore procedures
- [ ] Create security update procedures
- [ ] Document monitoring and alerting setup

### Post-Deployment
- [ ] **Regular maintenance**
  - [ ] Schedule weekly security updates check
  - [ ] Monthly review of logs for anomalies
  - [ ] Quarterly security audit
  - [ ] Annual penetration testing
- [ ] **Update procedures**
  - [ ] Test updates in staging environment first
  - [ ] Have rollback plan ready
  - [ ] Schedule updates during low-traffic periods
  - [ ] Monitor closely after updates

## 🚨 Emergency Response

### In case of security breach:
1. **Immediate actions**
   - [ ] Take application offline if necessary
   - [ ] Revoke all user sessions
   - [ ] Change all secrets (JWT, session, database)
   - [ ] Review audit logs to determine scope

2. **Investigation**
   - [ ] Identify attack vector
   - [ ] Determine data accessed/modified
   - [ ] Check for backdoors or persistent access

3. **Recovery**
   - [ ] Patch vulnerability
   - [ ] Reset all user passwords
   - [ ] Notify affected users
   - [ ] Document incident and lessons learned

## 📞 Security Contacts

- Security Officer: [Name] - [Email] - [Phone]
- System Administrator: [Name] - [Email] - [Phone]
- Database Administrator: [Name] - [Email] - [Phone]
- Emergency Contact: [Name] - [Email] - [Phone]

---

**Remember**: Security is an ongoing process, not a one-time setup. Regular reviews and updates are essential for maintaining a secure application.