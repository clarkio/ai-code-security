# Deployment Guide

## Quick Start Deployment

### 1. Prepare Your Environment

```bash
cd secure-notes-app
npm install
cp .env.example .env
```

### 2. Configure Environment Variables

Edit `.env` file with production values:

```bash
# REQUIRED - Generate a secure random secret
JWT_SECRET=$(openssl rand -base64 64)

# REQUIRED
NODE_ENV=production

# Server Configuration
PORT=3000

# Security Configuration
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
BCRYPT_ROUNDS=12

# CORS - Replace with your actual frontend domain
CORS_ORIGIN=https://your-app.com

# Database
DATABASE_PATH=./data/notes.db

# Cookie Security (if using cookies)
COOKIE_SECURE=true
COOKIE_SAME_SITE=strict
COOKIE_HTTP_ONLY=true
```

### 3. Initialize Database

```bash
npm run migrate
```

### 4. Start the Server

```bash
npm start
```

## Production Deployment Options

### Option 1: Using PM2 (Recommended)

Install PM2 globally:
```bash
npm install -g pm2
```

Start the application:
```bash
pm2 start server.js --name secure-notes
```

Configure PM2 to start on boot:
```bash
pm2 startup
pm2 save
```

Monitor the application:
```bash
pm2 logs secure-notes
pm2 monit
```

### Option 2: Using systemd

Create `/etc/systemd/system/secure-notes.service`:

```ini
[Unit]
Description=Secure Notes API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/secure-notes-app
ExecStart=/usr/bin/node /var/www/secure-notes-app/server.js
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=secure-notes
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable secure-notes
sudo systemctl start secure-notes
sudo systemctl status secure-notes
```

### Option 3: Using Docker

Create `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN mkdir -p data

EXPOSE 3000

CMD ["node", "server.js"]
```

Create `.dockerignore`:

```
node_modules
npm-debug.log
.env
.git
data
*.md
```

Build and run:
```bash
docker build -t secure-notes .
docker run -d -p 3000:3000 --name secure-notes \
  -e JWT_SECRET=your-secret-here \
  -e NODE_ENV=production \
  -v $(pwd)/data:/app/data \
  secure-notes
```

## Reverse Proxy Configuration

### Nginx Configuration

Create `/etc/nginx/sites-available/secure-notes`:

```nginx
upstream secure_notes_backend {
    server localhost:3000;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Logging
    access_log /var/log/nginx/secure-notes-access.log;
    error_log /var/log/nginx/secure-notes-error.log;

    # Proxy Configuration
    location / {
        proxy_pass http://secure_notes_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/secure-notes /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Apache Configuration

Enable required modules:
```bash
sudo a2enmod proxy proxy_http rewrite ssl headers
```

Create virtual host config:

```apache
<VirtualHost *:80>
    ServerName your-domain.com
    Redirect permanent / https://your-domain.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName your-domain.com
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/your-domain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/your-domain.com/privkey.pem
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5
    
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyPreserveHost On
    ProxyPass / http://localhost:3000/
    ProxyPassReverse / http://localhost:3000/
    
    ErrorLog ${APACHE_LOG_DIR}/secure-notes-error.log
    CustomLog ${APACHE_LOG_DIR}/secure-notes-access.log combined
</VirtualHost>
```

## SSL/TLS Setup

### Using Let's Encrypt with Certbot

```bash
sudo apt-get install certbot python3-certbot-nginx

# For nginx
sudo certbot --nginx -d your-domain.com

# For Apache
sudo certbot --apache -d your-domain.com

# Auto-renewal (certbot sets this up automatically)
sudo certbot renew --dry-run
```

## Database Backup

### Automated Backup Script

Create `backup.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/var/backups/secure-notes"
DATE=$(date +%Y%m%d_%H%M%S)
DB_PATH="/var/www/secure-notes-app/data/notes.db"
BACKUP_FILE="$BACKUP_DIR/notes_$DATE.db.gz"

mkdir -p $BACKUP_DIR
gzip -c $DB_PATH > $BACKUP_FILE

# Keep only last 7 days of backups
find $BACKUP_DIR -name "notes_*.db.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE"
```

Make executable and add to crontab:
```bash
chmod +x backup.sh
crontab -e
```

Add line for daily backup at 2 AM:
```
0 2 * * * /path/to/backup.sh >> /var/log/backup.log 2>&1
```

## Monitoring

### Health Check Endpoint

The application includes a health check endpoint:
```
GET /health
```

Returns:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-13T10:00:00.000Z"
}
```

### Log Monitoring

View application logs:
```bash
# With PM2
pm2 logs secure-notes

# With systemd
sudo journalctl -u secure-notes -f

# With Docker
docker logs -f secure-notes
```

### Uptime Monitoring

Consider using external monitoring services:
- UptimeRobot
- Pingdom
- StatusCake
- Datadog

## Security Hardening

### Firewall Configuration

Using UFW:
```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### File Permissions

```bash
# Set appropriate permissions
chmod 600 /var/www/secure-notes-app/.env
chmod 755 /var/www/secure-notes-app
chmod 644 /var/www/secure-notes-app/*.js
chmod 700 /var/www/secure-notes-app/data
chmod 600 /var/www/secure-notes-app/data/notes.db
```

### Dependency Updates

Regularly update dependencies:
```bash
npm audit
npm audit fix
npm update
```

## Scaling Considerations

### Horizontal Scaling

For multiple instances:
1. Use a load balancer (nginx, HAProxy, AWS ALB)
2. Share database (use PostgreSQL or MySQL instead of SQLite)
3. Implement session storage (Redis for JWT blacklist if needed)
4. Use shared storage for static assets

### Database Migration

For production with multiple instances, migrate from SQLite to PostgreSQL:

1. Install PostgreSQL adapter:
```bash
npm install pg
```

2. Update database configuration to use connection pooling
3. Migrate existing data
4. Update deployment configuration

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Find process using port 3000
sudo lsof -i :3000
# Kill the process
sudo kill -9 <PID>
```

**Database locked:**
```bash
# Check for WAL files
ls -la data/
# Restart application to release locks
pm2 restart secure-notes
```

**Memory issues:**
```bash
# Check memory usage
pm2 monit
# Increase Node.js memory limit
node --max-old-space-size=4096 server.js
```

### Performance Tuning

**Increase rate limits for legitimate traffic:**
```bash
# In .env
RATE_LIMIT_MAX_REQUESTS=200
RATE_LIMIT_WINDOW_MS=60000
```

**Optimize database queries:**
- Ensure indexes are created (already included in migration)
- Consider pagination for large datasets
- Implement caching for frequently accessed data

## Post-Deployment Checklist

- [ ] Application starts successfully
- [ ] Health check endpoint responds
- [ ] SSL/TLS certificate is valid
- [ ] CORS is configured correctly
- [ ] Rate limiting is working
- [ ] Database backups are scheduled
- [ ] Logs are being collected
- [ ] Monitoring is configured
- [ ] Security headers are present
- [ ] Firewall rules are active
- [ ] File permissions are correct
- [ ] Dependencies are up to date
- [ ] Error handling tested
- [ ] Load testing performed
- [ ] Documentation updated
