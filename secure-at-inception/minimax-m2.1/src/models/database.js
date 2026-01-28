/**
 * Secure Database Layer
 * Uses parameterized queries to prevent SQL injection
 */
const Database = require('better-sqlite3');
const path = require('path');
const config = require('../config.json');
const logger = require('../utils/logger');

class DatabaseLayer {
  constructor() {
    this.db = null;
  }

  /**
   * Initialize database connection and create tables
   */
  initialize() {
    const dbPath = path.resolve(__dirname, '../../', config.database.path);
    
    // Ensure data directory exists
    const fs = require('fs');
    const dataDir = path.dirname(dbPath);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL'); // Use Write-Ahead Logging for better concurrency
    this.createTables();
    logger.info('Database initialized successfully');
  }

  /**
   * Create database tables with proper schema
   */
  createTables() {
    // Users table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME
      )
    `);

    // Notes table with foreign key to users
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS notes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Sessions table for JWT blacklisting
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Create indexes for performance
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    `);
  }

  /**
   * Execute a safe query with parameterized statements
   */
  query(sql, params = []) {
    try {
      const stmt = this.db.prepare(sql);
      return stmt.all(params);
    } catch (error) {
      logger.error('Database query error', { sql, error: error.message });
      throw error;
    }
  }

  /**
   * Execute a safe statement (insert/update/delete)
   */
  run(sql, params = []) {
    try {
      const stmt = this.db.prepare(sql);
      return stmt.run(params);
    } catch (error) {
      logger.error('Database statement error', { sql, error: error.message });
      throw error;
    }
  }

  /**
   * Get a single row
   */
  get(sql, params = []) {
    try {
      const stmt = this.db.prepare(sql);
      return stmt.get(params);
    } catch (error) {
      logger.error('Database get error', { sql, error: error.message });
      throw error;
    }
  }

  /**
   * Close database connection
   */
  close() {
    if (this.db) {
      this.db.close();
      logger.info('Database connection closed');
    }
  }
}

// Singleton instance
const dbLayer = new DatabaseLayer();

module.exports = dbLayer;
