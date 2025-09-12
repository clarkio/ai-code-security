# 🔒 Production Deployment Security Guide

## ⚠️ CRITICAL WARNING
**YOUR JOB DEPENDS ON THE SECURITY OF THIS APPLICATION**

This guide contains MANDATORY security steps that MUST be completed before deploying to production.

## 🚨 Pre-Deployment Security Steps

### 1. Generate Production Secrets (MANDATORY)

```bash
# Generate secure secrets on your LOCAL machine (not on the server)
npm run generate-secrets
```

Copy these values and use them in your production environment. **NEVER reuse development secrets!**

### 2. Environment Configuration

Create a production `.env` file with these MANDATORY changes:

```env
NODE_ENV=production
SESSION_SECURE=true
SESSION_SECRET=[YOUR_GENERATED_64_CHAR_SECRET]
JWT_SECRET=[YOUR_GENERATED_64_CHAR_SECRET]
ALLOWED_ORIGINS=https://yourdomain.com
ENABLE_TRUST_PROXY=true
```

### 3. HTTPS Configuration (MANDATORY)

The application MUST be served over HTTPS. Options:

#### Option A: Nginx Reverse Proxy
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }
}
```

#### Option B: Cloud Provider (Heroku, AWS, etc.)
Ensure SSL is enabled in your cloud provider's settings.

## 🛡️ Server Hardening

### 1. Create Non-Root User
```bash
# Create application user
sudo adduser nodeapp --disabled-password
sudo usermod -aG nodeapp nodeapp

# Set up application directory
sudo mkdir -p /opt/secure-notes-app
sudo chown -R nodeapp:nodeapp /opt/secure-notes-app
```

### 2. Set File Permissions
```bash
# Restrictive permissions
sudo chmod 750 /opt/secure-notes-app
sudo chmod 640 /opt/secure-notes-app/.env
sudo chmod 750 /opt/secure-notes-app/node_modules
```

### 3. Systemd Service (for Linux servers)

Create `/etc/systemd/system/secure-notes.service`:

```ini
[Unit]
Description=Secure Notes Application
After=network.target

[Service]
Type=simple
User=nodeapp
WorkingDirectory=/opt/secure-notes-app
ExecStart=/usr/bin/node app.js
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/secure-notes-app/data /opt/secure-notes-app/logs

# Environment
Environment="NODE_ENV=production"
EnvironmentFile=/opt/secure-notes-app/.env

[Install]
WantedBy=multi-user.target
```

### 4. Firewall Configuration
```bash
# Only allow necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 📊 Database Security

### For SQLite (current setup):
```bash
# Secure database file
chmod 600 /opt/secure-notes-app/data/database.sqlite
```

### For Production (PostgreSQL recommended):
```sql
-- Create database and user
CREATE DATABASE secure_notes_prod;
CREATE USER notes_app WITH ENCRYPTED PASSWORD 'strong_password_here';
GRANT CONNECT ON DATABASE secure_notes_prod TO notes_app;
GRANT USAGE ON SCHEMA public TO notes_app;
GRANT CREATE ON SCHEMA public TO notes_app;

-- Enable SSL
ALTER SYSTEM SET ssl = on;
```

## 🔍 Security Monitoring

### 1. Set Up Logging
```bash
# Create log directory
sudo mkdir -p /var/log/secure-notes
sudo chown nodeapp:nodeapp /var/log/secure-notes

# Configure logrotate
sudo nano /etc/logrotate.d/secure-notes
```

Add:
```
/var/log/secure-notes/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 nodeapp nodeapp
    sharedscripts
}
```

### 2. Monitor Failed Logins
```bash
# Watch for failed login attempts
tail -f /opt/secure-notes-app/logs/app.log | grep "LOGIN_ATTEMPT\|FAILED"
```

### 3. Set Up Alerts
Configure monitoring for:
- Multiple failed login attempts from same IP
- Rate limit violations
- Application errors
- Unusual traffic patterns

## 🚀 Deployment Steps

### 1. Deploy Application
```bash
# As nodeapp user
sudo -u nodeapp bash
cd /opt/secure-notes-app

# Clone/copy application files
git clone [repository] .

# Install production dependencies only
npm ci --production

# Set up environment
cp .env.example .env
# Edit .env with production values
nano .env
```

### 2. Start Application
```bash
# Enable and start service
sudo systemctl enable secure-notes
sudo systemctl start secure-notes

# Check status
sudo systemctl status secure-notes
```

### 3. Verify Security Headers
Visit: https://securityheaders.com/?q=yourdomain.com

All headers should show green checkmarks.

## ✅ Post-Deployment Checklist

- [ ] HTTPS is working (test with SSL Labs)
- [ ] Default secrets have been changed
- [ ] Rate limiting is active
- [ ] Login with weak password fails
- [ ] Account lockout after 5 attempts works
- [ ] CSRF protection is active
- [ ] Security headers show A+ rating
- [ ] Monitoring is configured
- [ ] Backups are scheduled
- [ ] Logs are being collected
- [ ] Firewall is configured
- [ ] Application runs as non-root user

## 🆘 Emergency Procedures

### If Compromised:
1. Take application offline immediately
2. Preserve logs for investigation
3. Reset all user passwords
4. Generate new application secrets
5. Review access logs
6. Notify affected users
7. Document incident

### Security Contacts:
- Security Team: [email]
- On-Call: [phone]
- Escalation: [manager]

## 📅 Maintenance Schedule

### Daily:
- Review security logs
- Check for failed login patterns

### Weekly:
- Run security scanner
- Review rate limit violations
- Check for updates

### Monthly:
- Update dependencies
- Rotate secrets
- Security audit
- Backup verification

## ⚠️ FINAL WARNING

**DO NOT DEPLOY WITHOUT COMPLETING ALL SECURITY STEPS**

Your job security depends on the application security. When in doubt, ask for help from the security team.

---
Last Updated: [Date]
Approved By: [Security Team Lead]