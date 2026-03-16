const fs = require("node:fs");
const path = require("node:path");

const dotenv = require("dotenv");

const { hashPassword } = require("./security");

dotenv.config();

function toPositiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function toBoolean(value) {
  return value === "1" || value === "true";
}

function loadConfig(overrides = {}) {
  const env = overrides.env || process.env.NODE_ENV || "development";
  const isProduction = env === "production";
  const rootDir = overrides.rootDir || path.resolve(__dirname, "..");
  const dataDir = overrides.dataDir || path.join(rootDir, "data");

  fs.mkdirSync(dataDir, { recursive: true });

  const sessionSecret = overrides.sessionSecret || process.env.SESSION_SECRET;
  const adminUsername =
    overrides.adminUsername || process.env.ADMIN_USERNAME || "admin";
  const adminPasswordHash =
    overrides.adminPasswordHash ||
    process.env.ADMIN_PASSWORD_HASH ||
    (!isProduction ? hashPassword("change-me-now") : undefined);

  if (isProduction && !sessionSecret) {
    throw new Error("SESSION_SECRET must be set in production.");
  }

  if (isProduction && !adminPasswordHash) {
    throw new Error("ADMIN_PASSWORD_HASH must be set in production.");
  }

  return {
    env,
    isProduction,
    port: overrides.port || toPositiveInteger(process.env.PORT, 3000),
    trustProxy: overrides.trustProxy ?? toBoolean(process.env.TRUST_PROXY),
    rootDir,
    dataDir,
    databasePath: overrides.databasePath || path.join(dataDir, "notes.json"),
    sessionDir: overrides.sessionDir || path.join(dataDir, "sessions"),
    sessionSecret: sessionSecret || "development-only-session-secret-change-me",
    adminUsername,
    adminPasswordHash,
    sessionCookieName: "notes.sid",
    sessionDurationMs: 1000 * 60 * 60 * 8,
    bodyLimit: "10kb",
    globalRateLimitMax: overrides.globalRateLimitMax || 100,
    authRateLimitMax: overrides.authRateLimitMax || 10,
  };
}

module.exports = {
  loadConfig,
};
