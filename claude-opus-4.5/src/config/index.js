/**
 * Application Configuration
 * Centralizes all configuration with validation and secure defaults
 */

require("dotenv").config();

const config = {
  // Server
  env: process.env.NODE_ENV || "development",
  port: parseInt(process.env.PORT, 10) || 3000,
  host: process.env.HOST || "localhost",

  // Security
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || "15m",
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
  },

  session: {
    secret: process.env.SESSION_SECRET,
  },

  // Rate Limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000, // 15 minutes
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
  },

  // Database
  database: {
    path: process.env.DATABASE_PATH || "./data/notes.db",
  },

  // CORS
  cors: {
    origins: process.env.CORS_ORIGINS
      ? process.env.CORS_ORIGINS.split(",").map((o) => o.trim())
      : ["http://localhost:3000"],
  },

  // Cookies
  cookie: {
    secure: process.env.COOKIE_SECURE === "true",
    sameSite: process.env.COOKIE_SAME_SITE || "strict",
  },

  // Logging
  logging: {
    level: process.env.LOG_LEVEL || "info",
  },
};

/**
 * Validate critical configuration
 */
function validateConfig() {
  const errors = [];

  // In production, require strong secrets
  if (config.env === "production") {
    if (!config.jwt.secret || config.jwt.secret.length < 32) {
      errors.push("JWT_SECRET must be at least 32 characters in production");
    }
    if (config.jwt.secret && config.jwt.secret.includes("CHANGE_THIS")) {
      errors.push(
        "JWT_SECRET contains default value - must be changed in production"
      );
    }

    if (!config.session.secret || config.session.secret.length < 32) {
      errors.push(
        "SESSION_SECRET must be at least 32 characters in production"
      );
    }
    if (
      config.session.secret &&
      config.session.secret.includes("CHANGE_THIS")
    ) {
      errors.push(
        "SESSION_SECRET contains default value - must be changed in production"
      );
    }

    if (!config.cookie.secure) {
      errors.push("COOKIE_SECURE must be true in production");
    }
  }

  // Development defaults for secrets (only for local development!)
  if (config.env !== "production") {
    if (!config.jwt.secret) {
      config.jwt.secret =
        "dev-only-jwt-secret-do-not-use-in-production-" + Date.now();
    }
    if (!config.session.secret) {
      config.session.secret =
        "dev-only-session-secret-do-not-use-in-production-" + Date.now();
    }
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.join("\n")}`);
  }

  return config;
}

module.exports = validateConfig();
