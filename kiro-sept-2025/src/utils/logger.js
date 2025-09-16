const winston = require('winston');
const path = require('path');
const fs = require('fs');
const config = require('../config/environment');

// Custom format for security-focused logging
const securityFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    // Redact sensitive information
    const sanitizedMeta = sanitizeLogData(meta);
    
    return JSON.stringify({
      timestamp,
      level,
      message,
      ...sanitizedMeta
    });
  })
);

// Function to sanitize sensitive data from logs
function sanitizeLogData(data) {
  const sensitiveFields = [
    'password', 'token', 'secret', 'key', 'authorization',
    'cookie', 'session', 'jwt', 'refresh_token', 'access_token'
  ];
  
  const sanitized = { ...data };
  
  // Recursively sanitize object with circular reference protection
  function sanitizeObject(obj, visited = new WeakSet()) {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }
    
    // Check for circular references
    if (visited.has(obj)) {
      return '[Circular Reference]';
    }
    
    visited.add(obj);
    
    const result = Array.isArray(obj) ? [] : {};
    
    try {
      for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        
        if (sensitiveFields.some(field => lowerKey.includes(field))) {
          result[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
          result[key] = sanitizeObject(value, visited);
        } else {
          result[key] = value;
        }
      }
    } catch (error) {
      // Handle any errors during sanitization
      return '[Sanitization Error]';
    }
    
    visited.delete(obj);
    return result;
  }
  
  return sanitizeObject(sanitized);
}

// Create logger instance
const logger = winston.createLogger({
  level: config.logging.level,
  format: securityFormat,
  defaultMeta: {
    service: 'secure-notes-app',
    environment: config.app.env
  },
  transports: [
    // Console transport for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ],
  // Handle uncaught exceptions and rejections
  exceptionHandlers: [
    new winston.transports.Console()
  ],
  rejectionHandlers: [
    new winston.transports.Console()
  ]
});

// Add file transport for production and development (for testing)
if (config.app.env === 'production' || config.app.env === 'development') {
  // Ensure logs directory exists
  const logDir = path.dirname(config.logging.file);
  
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true, mode: 0o750 }); // Secure directory permissions
  }
  
  // Main application log with rotation
  logger.add(new winston.transports.File({
    filename: config.logging.file,
    maxsize: 10485760, // 10MB
    maxFiles: 10, // Keep more files for better audit trail
    tailable: true,
    format: securityFormat
  }));
  
  // Separate file for errors with rotation
  logger.add(new winston.transports.File({
    filename: path.join(logDir, 'error.log'),
    level: 'error',
    maxsize: 10485760, // 10MB
    maxFiles: 10,
    tailable: true,
    format: securityFormat
  }));
  
  // Separate file for security events
  logger.add(new winston.transports.File({
    filename: path.join(logDir, 'security.log'),
    level: 'info',
    maxsize: 10485760, // 10MB
    maxFiles: 15, // Keep more security logs for compliance
    tailable: true,
    format: securityFormat,
    // Only log security events
    filter: (info) => {
      return info.event && info.event.includes('auth_') || 
             info.event && info.event.includes('security_') ||
             info.event && info.event.includes('data_') ||
             info.event && info.event.includes('rate_limit');
    }
  }));
  
  // Separate file for audit trail
  logger.add(new winston.transports.File({
    filename: path.join(logDir, 'audit.log'),
    level: 'info',
    maxsize: 20971520, // 20MB for audit logs
    maxFiles: 20, // Keep more audit logs for compliance
    tailable: true,
    format: securityFormat,
    // Only log audit events
    filter: (info) => {
      return info.event && (
        info.event.includes('data_') ||
        info.event.includes('auth_') ||
        info.event === 'audit_event'
      );
    }
  }));
}

// Security event logging methods
logger.security = {
  authAttempt: (data) => {
    logger.info('Authentication attempt', {
      event: 'auth_attempt',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  authSuccess: (data) => {
    logger.info('Authentication successful', {
      event: 'auth_success',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  authFailure: (data) => {
    logger.warn('Authentication failed', {
      event: 'auth_failure',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  authLockout: (data) => {
    logger.error('Account locked due to failed attempts', {
      event: 'auth_lockout',
      timestamp: new Date().toISOString(),
      severity: 'high',
      ...data
    });
  },
  
  dataAccess: (data) => {
    logger.info('Data access', {
      event: 'data_access',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  dataModification: (data) => {
    logger.info('Data modification', {
      event: 'data_modification',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  securityViolation: (data) => {
    logger.error('Security violation detected', {
      event: 'security_violation',
      timestamp: new Date().toISOString(),
      severity: 'critical',
      ...data
    });
  },
  
  rateLimitExceeded: (data) => {
    logger.warn('Rate limit exceeded', {
      event: 'rate_limit_exceeded',
      timestamp: new Date().toISOString(),
      severity: 'medium',
      ...data
    });
  },
  
  // Additional security events
  sessionHijackAttempt: (data) => {
    logger.error('Session hijack attempt detected', {
      event: 'security_violation',
      subEvent: 'session_hijack_attempt',
      timestamp: new Date().toISOString(),
      severity: 'critical',
      ...data
    });
  },
  
  suspiciousActivity: (data) => {
    logger.warn('Suspicious activity detected', {
      event: 'security_violation',
      subEvent: 'suspicious_activity',
      timestamp: new Date().toISOString(),
      severity: 'medium',
      ...data
    });
  },
  
  privilegeEscalation: (data) => {
    logger.error('Privilege escalation attempt', {
      event: 'security_violation',
      subEvent: 'privilege_escalation',
      timestamp: new Date().toISOString(),
      severity: 'critical',
      ...data
    });
  },
  
  dataExfiltration: (data) => {
    logger.error('Potential data exfiltration detected', {
      event: 'security_violation',
      subEvent: 'data_exfiltration',
      timestamp: new Date().toISOString(),
      severity: 'critical',
      ...data
    });
  }
};

// Audit trail logging methods
logger.audit = {
  logEvent: (data) => {
    logger.info('Audit event', {
      event: 'audit_event',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  userAction: (data) => {
    logger.info('User action audit', {
      event: 'audit_event',
      subEvent: 'user_action',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  systemAction: (data) => {
    logger.info('System action audit', {
      event: 'audit_event',
      subEvent: 'system_action',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  configurationChange: (data) => {
    logger.warn('Configuration change audit', {
      event: 'audit_event',
      subEvent: 'configuration_change',
      timestamp: new Date().toISOString(),
      ...data
    });
  }
};

// Health and monitoring methods
logger.health = {
  systemHealth: (data) => {
    logger.info('System health check', {
      event: 'health_check',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  performanceMetric: (data) => {
    logger.info('Performance metric', {
      event: 'performance_metric',
      timestamp: new Date().toISOString(),
      ...data
    });
  },
  
  resourceUsage: (data) => {
    logger.info('Resource usage', {
      event: 'resource_usage',
      timestamp: new Date().toISOString(),
      ...data
    });
  }
};

// Log management utilities
logger.management = {
  /**
   * Get log statistics for monitoring
   */
  getLogStats: () => {
    const stats = {
      level: logger.level,
      transports: logger.transports.length,
      environment: config.app.env,
      timestamp: new Date().toISOString()
    };
    
    return stats;
  },
  
  /**
   * Rotate logs manually (for testing or maintenance)
   */
  rotateLogs: () => {
    logger.transports.forEach(transport => {
      if (transport.filename && typeof transport.rotate === 'function') {
        transport.rotate();
      }
    });
    
    logger.info('Manual log rotation completed', {
      event: 'log_rotation',
      timestamp: new Date().toISOString()
    });
  },
  
  /**
   * Set log level dynamically
   */
  setLogLevel: (level) => {
    const validLevels = ['error', 'warn', 'info', 'debug'];
    
    if (!validLevels.includes(level)) {
      throw new Error(`Invalid log level: ${level}. Valid levels: ${validLevels.join(', ')}`);
    }
    
    logger.level = level;
    
    logger.info('Log level changed', {
      event: 'log_level_change',
      newLevel: level,
      timestamp: new Date().toISOString()
    });
  },
  
  /**
   * Get current log configuration
   */
  getConfig: () => {
    return {
      level: logger.level,
      environment: config.app.env,
      logFile: config.logging.file,
      transports: logger.transports.map(transport => ({
        type: transport.constructor.name,
        level: transport.level,
        filename: transport.filename || null
      }))
    };
  }
};

// Export logger with additional metadata
logger.version = '1.0.0';
logger.initialized = new Date().toISOString();

module.exports = logger;