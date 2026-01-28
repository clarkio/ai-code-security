/**
 * Secure Logger Utility
 * Implements structured logging with security event tracking
 */
const winston = require('winston');
const config = require('../config/default.json');

const logger = winston.createLogger({
  level: config.logging.level,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'secure-notes-app' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Security event logging
logger.securityEvent = (eventType, details) => {
  logger.warn({
    type: 'security',
    event: eventType,
    ...details
  });
};

// Request logging
logger.requestLog = (method, path, ip, userId, statusCode, duration) => {
  logger.info({
    type: 'request',
    method,
    path,
    ip,
    userId,
    statusCode,
    duration: `${duration}ms`
  });
};

module.exports = logger;
