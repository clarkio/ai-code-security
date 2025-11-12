#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const winston = require('winston');

// Security monitoring script
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/security-monitor.log' })
  ]
});

class SecurityMonitor {
  constructor() {
    this.logFile = path.join(__dirname, '../logs/combined.log');
    this.errorFile = path.join(__dirname, '../logs/error.log');
    this.suspiciousPatterns = [
      /SQL injection/i,
      /XSS/i,
      /CSRF/i,
      /directory traversal/i,
      /\.\.\//,
      /<script/i,
      /javascript:/i,
      /union.*select/i,
      /drop.*table/i,
      /admin/i,
      /root/i
    ];
  }

  async checkLogs() {
    try {
      const logs = await this.readLogFile(this.logFile);
      const errors = await this.readLogFile(this.errorFile);
      
      const suspiciousActivity = this.analyzeLogs([...logs, ...errors]);
      
      if (suspiciousActivity.length > 0) {
        logger.warn('Suspicious activity detected:', suspiciousActivity);
        this.sendAlert(suspiciousActivity);
      }
      
      logger.info(`Security monitor completed. Found ${suspiciousActivity.length} suspicious entries.`);
    } catch (error) {
      logger.error('Error in security monitor:', error);
    }
  }

  async readLogFile(filePath) {
    if (!fs.existsSync(filePath)) {
      return [];
    }
    
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.trim().split('\n').filter(line => line.trim());
    
    return lines.map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return { message: line, timestamp: new Date().toISOString() };
      }
    });
  }

  analyzeLogs(logs) {
    const suspicious = [];
    
    logs.forEach(log => {
      const logString = JSON.stringify(log).toLowerCase();
      
      this.suspiciousPatterns.forEach(pattern => {
        if (pattern.test(logString)) {
          suspicious.push({
            ...log,
            pattern: pattern.toString(),
            severity: this.getSeverity(pattern)
          });
        }
      });
    });
    
    return suspicious;
  }

  getSeverity(pattern) {
    const highSeverity = [/SQL injection/i, /XSS/i, /CSRF/i, /admin/i, /root/i];
    const mediumSeverity = [/\.\.\//, /<script/i, /javascript:/i];
    
    if (highSeverity.some(p => pattern.toString().includes(p.source))) {
      return 'HIGH';
    } else if (mediumSeverity.some(p => pattern.toString().includes(p.source))) {
      return 'MEDIUM';
    }
    
    return 'LOW';
  }

  sendAlert(suspiciousActivity) {
    const highSeverity = suspiciousActivity.filter(item => item.severity === 'HIGH');
    
    if (highSeverity.length > 0) {
      logger.error('🚨 HIGH SEVERITY SECURITY ALERT:', {
        count: highSeverity.length,
        activities: highSeverity.slice(0, 5), // Limit to first 5
        timestamp: new Date().toISOString()
      });
    }
    
    const mediumSeverity = suspiciousActivity.filter(item => item.severity === 'MEDIUM');
    if (mediumSeverity.length > 0) {
      logger.warn('⚠️ MEDIUM SEVERITY SECURITY ALERT:', {
        count: mediumSeverity.length,
        activities: mediumSeverity.slice(0, 5),
        timestamp: new Date().toISOString()
      });
    }
  }

  async checkFileIntegrity() {
    const criticalFiles = [
      'package.json',
      'server.js',
      'routes/notes.js',
      'middleware/validation.js'
    ];
    
    const integrityFile = path.join(__dirname, '../logs/file-integrity.json');
    let previousHashes = {};
    
    if (fs.existsSync(integrityFile)) {
      previousHashes = JSON.parse(fs.readFileSync(integrityFile, 'utf8'));
    }
    
    const currentHashes = {};
    const changes = [];
    
    for (const file of criticalFiles) {
      const filePath = path.join(__dirname, '..', file);
      if (fs.existsSync(filePath)) {
        const stats = fs.statSync(filePath);
        const hash = `${stats.size}-${stats.mtime.getTime()}`;
        currentHashes[file] = hash;
        
        if (previousHashes[file] && previousHashes[file] !== hash) {
          changes.push({
            file,
            previousHash: previousHashes[file],
            currentHash: hash,
            changedAt: new Date().toISOString()
          });
        }
      }
    }
    
    if (changes.length > 0) {
      logger.warn('File integrity changes detected:', changes);
    }
    
    fs.writeFileSync(integrityFile, JSON.stringify(currentHashes, null, 2));
  }
}

// Run security monitor
if (require.main === module) {
  const monitor = new SecurityMonitor();
  
  logger.info('Starting security monitor...');
  
  monitor.checkLogs().then(() => {
    return monitor.checkFileIntegrity();
  }).then(() => {
    logger.info('Security monitor completed successfully');
    process.exit(0);
  }).catch(error => {
    logger.error('Security monitor failed:', error);
    process.exit(1);
  });
}

module.exports = SecurityMonitor;
