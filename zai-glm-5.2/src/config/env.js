"use strict";

/**
 * Environment configuration with validation.
 * Fails fast if required secrets are missing or insecure in production.
 */

const dotenv = require("dotenv");
const path = require("path");

// Load .env only in non-production (production should inject env vars directly)
if (process.env.NODE_ENV !== "production") {
  dotenv.config({ path: path.resolve(process.cwd(), ".env") });
}

function required(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (value === undefined || value === "") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

const nodeEnv = process.env.NODE_ENV || "development";
const isProduction = nodeEnv === "production";

const sessionSecret = required("SESSION_SECRET", "");

// SECURITY: refuse to boot in production with a weak/default secret
if (isProduction && sessionSecret.length < 64) {
  throw new Error(
    "SESSION_SECRET must be at least 64 characters in production. " +
      "Generate one with: node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\"",
  );
}
if (isProduction && /CHANGE_ME|xxxx/i.test(sessionSecret)) {
  throw new Error(
    "SESSION_SECRET appears to be a placeholder. Set a real secret in production.",
  );
}

module.exports = {
  nodeEnv,
  isProduction,
  port: parseInt(process.env.PORT || "3000", 10),
  sessionSecret,
  dbPath:
    process.env.DB_PATH || path.resolve(process.cwd(), "data", "notes.db"),
  redisUrl: process.env.REDIS_URL,
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000", 10),
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || "100", 10),
  trustProxy: parseInt(process.env.TRUST_PROXY || "0", 10),
  // When true, rate limiting is disabled (TESTING ONLY — never enable in production)
  disableRateLimit: process.env.DISABLE_RATE_LIMIT === "true",
};
