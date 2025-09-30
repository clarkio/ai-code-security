# Production Deployment Guide

## Pre-Deployment Security Checklist

### 1. Environment Configuration

#### Generate Strong Secrets

Use the following commands to generate cryptographically secure random secrets:

**Linux/Mac:**

```bash
# Generate JWT secret
openssl rand -base64 48

# Generate Cookie secret
openssl rand -base64 48
```

**Windows (PowerShell):**

```powershell
# Generate JWT secret
[Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }))

# Generate Cookie secret
[Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }))
```

**Node.js:**

```javascript
const crypto = require("crypto");
console.log("JWT_SECRET:", crypto.randomBytes(48).toString("base64"));
console.log("COOKIE_SECRET:", crypto.randomBytes(48).toString("base64"));
```

#### Update .env File

```env
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# CRITICAL: Replace these with your generated secrets
JWT_SECRET=<your-generated-jwt-secret-here>
JWT_EXPIRE=24h
JWT_COOKIE_EXPIRE=1

COOKIE_SECRET=<your-generated-cookie-secret-here>

# Set your production domain(s)
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Adjust rate limits based on your needs
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Security settings
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_TIME=900000
```

### 2. Database Setup

Replace in-memory storage with a proper database:

#### PostgreSQL Example

1. Install PostgreSQL driver:

```bash
npm install pg
```

2. Update User model (`src/models/User.js`):

```javascript
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

class User {
  static async create(userData) {
    const query = `
      INSERT INTO users (id, username, password, created_at)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;
    const result = await pool.query(query, [
      userData.id,
      userData.username,
      userData.password,
      userData.createdAt,
    ]);
    return result.rows[0];
  }

  // Implement other methods...
}
```

3. Create database schema:

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  username VARCHAR(30) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  last_login TIMESTAMP
);

CREATE TABLE notes (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(200) NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_notes_user_id ON notes(user_id);
CREATE INDEX idx_users_username ON users(username);
```

### 3. Redis Setup for Rate Limiting

For multi-instance deployments:

1. Install Redis dependencies:

```bash
npm install redis rate-limit-redis
```

2. Update rate limiting in `src/server.js`:

```javascript
const redis = require("redis");
const RedisStore = require("rate-limit-redis");

const redisClient = redis.createClient({
  url: process.env.REDIS_URL,
});

const limiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: "rate_limit:",
  }),
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS),
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS),
});
```

### 4. HTTPS/TLS Configuration

#### Option A: Reverse Proxy (Recommended)

**Nginx Configuration:**

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

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

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

#### Option B: Let's Encrypt (Certbot)

```bash
# Install Certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal
sudo certbot renew --dry-run
```

### 5. Process Management with PM2

1. Install PM2:

```bash
npm install -g pm2
```

2. Create `ecosystem.config.js`:

```javascript
module.exports = {
  apps: [
    {
      name: "secure-notes-app",
      script: "./src/server.js",
      instances: "max",
      exec_mode: "cluster",
      env: {
        NODE_ENV: "production",
      },
      error_file: "./logs/err.log",
      out_file: "./logs/out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      max_memory_restart: "500M",
      watch: false,
      autorestart: true,
    },
  ],
};
```

3. Start application:

```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

### 6. Logging and Monitoring

1. Install Winston:

```bash
npm install winston winston-daily-rotate-file
```

2. Create `src/utils/logger.js`:

```javascript
const winston = require("winston");
const DailyRotateFile = require("winston-daily-rotate-file");

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new DailyRotateFile({
      filename: "logs/application-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      maxFiles: "30d",
      maxSize: "20m",
    }),
    new DailyRotateFile({
      filename: "logs/error-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      level: "error",
      maxFiles: "30d",
      maxSize: "20m",
    }),
  ],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

module.exports = logger;
```

### 7. Firewall Configuration

**UFW (Ubuntu):**

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 8. Security Scanning

1. Install security tools:

```bash
npm install -g snyk
snyk auth
snyk test
snyk monitor
```

2. Set up automated scanning in CI/CD:

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

### 9. Backup Strategy

Create automated backup script (`backup.sh`):

```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"

# Database backup
pg_dump $DATABASE_URL | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Application files backup
tar -czf "$BACKUP_DIR/app_$DATE.tar.gz" /path/to/app

# Keep only last 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

# Upload to S3 (optional)
# aws s3 cp "$BACKUP_DIR/db_$DATE.sql.gz" s3://your-bucket/backups/
```

Add to crontab:

```bash
0 2 * * * /path/to/backup.sh
```

### 10. Monitoring Setup

#### Health Check Endpoint

Already implemented at `/health`

#### Set up monitoring service (example with UptimeRobot):

1. Create account at uptimerobot.com
2. Add monitor for https://yourdomain.com/health
3. Set alert contacts

#### Application Performance Monitoring

Install New Relic (optional):

```bash
npm install newrelic
```

Create `newrelic.js` in root:

```javascript
exports.config = {
  app_name: ["Secure Notes App"],
  license_key: process.env.NEW_RELIC_LICENSE_KEY,
  logging: {
    level: "info",
  },
};
```

Update `server.js`:

```javascript
if (process.env.NODE_ENV === "production") {
  require("newrelic");
}
```

## Deployment Commands

### Initial Setup

```bash
# Clone repository
git clone <your-repo-url>
cd secure-notes-app

# Install dependencies
npm ci --production

# Set up environment
cp .env.example .env
nano .env  # Edit with production values

# Start with PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

### Updates

```bash
# Pull latest changes
git pull origin main

# Install dependencies
npm ci --production

# Restart application
pm2 restart secure-notes-app
```

## Security Incident Response

### If Credentials are Compromised:

1. **Immediately rotate secrets:**

```bash
# Generate new secrets
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"

# Update .env
# Restart application
pm2 restart secure-notes-app
```

2. **Force all users to re-authenticate:**

   - Clear all sessions
   - Invalidate all tokens
   - Notify users to change passwords

3. **Review logs for suspicious activity:**

```bash
pm2 logs --lines 1000 | grep "error\|unauthorized\|failed"
```

### Regular Security Maintenance

**Weekly:**

- Review application logs
- Check for failed authentication attempts
- Monitor resource usage

**Monthly:**

- Run `npm audit` and update dependencies
- Review and update security policies
- Test backup restoration
- Review access logs

**Quarterly:**

- Conduct security audit
- Penetration testing
- Review and update security documentation
- Team security training

## Support and Resources

- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- Node.js Security Best Practices: https://nodejs.org/en/docs/guides/security/
- Express Security Best Practices: https://expressjs.com/en/advanced/best-practice-security.html
- CWE Top 25: https://cwe.mitre.org/top25/
