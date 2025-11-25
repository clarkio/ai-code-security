/**
 * Secure Logger Configuration
 * Uses Winston with sanitization to prevent log injection
 */

const winston = require("winston");
const config = require("./index");

// Custom format to sanitize log messages (prevent log injection)
const sanitizeFormat = winston.format((info) => {
  // Remove or escape newlines and other control characters that could be used for log injection
  if (typeof info.message === "string") {
    info.message = info.message
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r")
      .replace(/\t/g, "\\t");
  }

  // Never log sensitive fields
  const sensitiveFields = [
    "password",
    "token",
    "secret",
    "authorization",
    "cookie",
  ];
  for (const field of sensitiveFields) {
    if (info[field]) {
      info[field] = "[REDACTED]";
    }
  }

  return info;
});

const logger = winston.createLogger({
  level: config.logging.level,
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    sanitizeFormat(),
    winston.format.errors({ stack: true }),
    config.env === "production"
      ? winston.format.json()
      : winston.format.combine(
          winston.format.colorize(),
          winston.format.printf(({ timestamp, level, message, ...meta }) => {
            const metaStr = Object.keys(meta).length
              ? JSON.stringify(meta)
              : "";
            return `${timestamp} [${level}]: ${message} ${metaStr}`;
          })
        )
  ),
  transports: [new winston.transports.Console()],
  // Don't exit on handled exceptions
  exitOnError: false,
});

// In production, also log to files
if (config.env === "production") {
  const fs = require("fs");
  const path = require("path");

  const logDir = path.join(__dirname, "../../logs");
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  logger.add(
    new winston.transports.File({
      filename: path.join(logDir, "error.log"),
      level: "error",
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    })
  );

  logger.add(
    new winston.transports.File({
      filename: path.join(logDir, "combined.log"),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    })
  );
}

module.exports = logger;
