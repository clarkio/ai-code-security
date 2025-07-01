const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define log colors
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

winston.addColors(colors);

// Define log format
const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json(),
  winston.format.printf((info) => {
    // Sanitize sensitive information
    if (info.password) info.password = '[REDACTED]';
    if (info.token) info.token = '[REDACTED]';
    if (info.authorization) info.authorization = '[REDACTED]';
    if (info.cookie) info.cookie = '[REDACTED]';
    
    return `${info.timestamp} ${info.level}: ${info.message} ${
      info.stack ? '\n' + info.stack : ''
    }`;
  })
);

// Define transports
const transports = [
  // Console transport
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize({ all: true }),
      format
    ),
  }),
  // File transport for errors
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    maxsize: 5242880, // 5MB
    maxFiles: 5,
  }),
  // File transport for all logs
  new winston.transports.File({
    filename: path.join(logsDir, 'app.log'),
    maxsize: 5242880, // 5MB
    maxFiles: 5,
  }),
];

// Create logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels,
  format,
  transports,
  exitOnError: false,
});

// Handle uncaught exceptions
logger.exceptions.handle(
  new winston.transports.File({
    filename: path.join(logsDir, 'exceptions.log'),
    maxsize: 5242880,
    maxFiles: 5,
  })
);

// Handle unhandled promise rejections
logger.rejections.handle(
  new winston.transports.File({
    filename: path.join(logsDir, 'rejections.log'),
    maxsize: 5242880,
    maxFiles: 5,
  })
);

// Create a stream object for Morgan
logger.stream = {
  write: (message) => logger.http(message.trim()),
};

module.exports = logger;