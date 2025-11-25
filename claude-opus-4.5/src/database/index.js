/**
 * Database Layer - SQLite with parameterized queries
 * All queries use parameters to prevent SQL injection
 */

const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const config = require("../config");
const logger = require("../config/logger");

// Ensure data directory exists
const dbDir = path.dirname(path.resolve(config.database.path));
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Initialize database with secure settings
const db = new Database(path.resolve(config.database.path), {
  // Enable Write-Ahead Logging for better performance and reliability
  verbose: config.env === "development" ? (msg) => logger.debug(msg) : null,
});

// Security hardening for SQLite
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("secure_delete = ON"); // Overwrite deleted data

/**
 * Initialize database schema
 */
function initializeDatabase() {
  logger.info("Initializing database schema...");

  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      failed_login_attempts INTEGER DEFAULT 0,
      locked_until TEXT,
      last_login TEXT
    )
  `);

  // Create indexes for users
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  `);

  // Notes table
  db.exec(`
    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create indexes for notes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
    CREATE INDEX IF NOT EXISTS idx_notes_created_at ON notes(created_at);
  `);

  // Refresh tokens table for secure token storage
  db.exec(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked INTEGER DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create indexes for refresh tokens
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
  `);

  // Audit log table for security events
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      resource TEXT,
      resource_id TEXT,
      ip_address TEXT,
      user_agent TEXT,
      details TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // Create indexes for audit log
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
  `);

  logger.info("Database schema initialized successfully");
}

/**
 * Clean up expired tokens and old audit logs periodically
 */
function cleanupExpiredData() {
  try {
    // Remove expired refresh tokens
    const deleteExpiredTokens = db.prepare(`
      DELETE FROM refresh_tokens
      WHERE datetime(expires_at) < datetime('now')
      OR revoked = 1
    `);
    const tokenResult = deleteExpiredTokens.run();

    // Remove audit logs older than 90 days
    const deleteOldAuditLogs = db.prepare(`
      DELETE FROM audit_log
      WHERE datetime(created_at) < datetime('now', '-90 days')
    `);
    const auditResult = deleteOldAuditLogs.run();

    if (tokenResult.changes > 0 || auditResult.changes > 0) {
      logger.info(
        `Cleanup: removed ${tokenResult.changes} expired tokens, ${auditResult.changes} old audit logs`
      );
    }
  } catch (error) {
    logger.error("Database cleanup error:", error);
  }
}

// Run cleanup periodically (every hour)
setInterval(cleanupExpiredData, 60 * 60 * 1000);

// Initialize on module load
initializeDatabase();

// Graceful shutdown
process.on("SIGINT", () => {
  logger.info("Closing database connection...");
  db.close();
  process.exit(0);
});

process.on("SIGTERM", () => {
  logger.info("Closing database connection...");
  db.close();
  process.exit(0);
});

module.exports = db;
