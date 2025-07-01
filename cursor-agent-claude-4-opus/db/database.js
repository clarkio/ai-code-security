const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');

// Ensure data directory exists
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = process.env.DATABASE_PATH || path.join(dataDir, 'notes.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    logger.error('Database connection error:', err);
  } else {
    logger.info('Connected to SQLite database');
  }
});

// Enable foreign keys
db.run('PRAGMA foreign_keys = ON');

// Initialize database schema
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        failed_login_attempts INTEGER DEFAULT 0,
        last_failed_login DATETIME,
        locked_until DATETIME
      )
    `);

    // Notes table
    db.run(`
      CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_deleted BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `);

    // Refresh tokens table
    db.run(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_revoked BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `);

    // Audit logs table
    db.run(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource_type TEXT,
        resource_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `);

    logger.info('Database initialized successfully');
  });
}

// Helper function to run queries with promises
function runQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function getOne(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function getAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// User operations
const userStatements = {
  create: async (params) => {
    const sql = `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`;
    return runQuery(sql, [params.username, params.email, params.password_hash]);
  },
  
  findByUsername: async (params) => {
    const sql = `SELECT * FROM users WHERE username = ? AND is_active = 1`;
    return getOne(sql, [params.username]);
  },
  
  findByEmail: async (params) => {
    const sql = `SELECT * FROM users WHERE email = ? AND is_active = 1`;
    return getOne(sql, [params.email]);
  },
  
  findById: async (params) => {
    const sql = `SELECT * FROM users WHERE id = ? AND is_active = 1`;
    return getOne(sql, [params.id]);
  },
  
  updateLoginAttempts: async (params) => {
    const sql = `UPDATE users SET failed_login_attempts = ?, last_failed_login = ? WHERE id = ?`;
    return runQuery(sql, [params.attempts, params.timestamp, params.id]);
  },
  
  lockAccount: async (params) => {
    const sql = `UPDATE users SET locked_until = ? WHERE id = ?`;
    return runQuery(sql, [params.locked_until, params.id]);
  },
  
  resetLoginAttempts: async (params) => {
    const sql = `UPDATE users SET failed_login_attempts = 0, last_failed_login = NULL, locked_until = NULL WHERE id = ?`;
    return runQuery(sql, [params.id]);
  }
};

// Note operations
const noteStatements = {
  create: async (params) => {
    const sql = `INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)`;
    return runQuery(sql, [params.user_id, params.title, params.content]);
  },
  
  findById: async (params) => {
    const sql = `SELECT * FROM notes WHERE id = ? AND user_id = ? AND is_deleted = 0`;
    return getOne(sql, [params.id, params.user_id]);
  },
  
  findByUser: async (params) => {
    const sql = `SELECT * FROM notes WHERE user_id = ? AND is_deleted = 0 ORDER BY updated_at DESC LIMIT ? OFFSET ?`;
    return getAll(sql, [params.user_id, params.limit, params.offset]);
  },
  
  update: async (params) => {
    const sql = `UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND is_deleted = 0`;
    return runQuery(sql, [params.title, params.content, params.id, params.user_id]);
  },
  
  softDelete: async (params) => {
    const sql = `UPDATE notes SET is_deleted = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`;
    return runQuery(sql, [params.id, params.user_id]);
  },
  
  countByUser: async (params) => {
    const sql = `SELECT COUNT(*) as count FROM notes WHERE user_id = ? AND is_deleted = 0`;
    return getOne(sql, [params.user_id]);
  }
};

// Token operations
const tokenStatements = {
  create: async (params) => {
    const sql = `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)`;
    return runQuery(sql, [params.user_id, params.token_hash, params.expires_at]);
  },
  
  findByHash: async (params) => {
    const sql = `SELECT * FROM refresh_tokens WHERE token_hash = ? AND is_revoked = 0`;
    return getOne(sql, [params.token_hash]);
  },
  
  revoke: async (params) => {
    const sql = `UPDATE refresh_tokens SET is_revoked = 1 WHERE token_hash = ?`;
    return runQuery(sql, [params.token_hash]);
  },
  
  revokeAllForUser: async (params) => {
    const sql = `UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = ? AND is_revoked = 0`;
    return runQuery(sql, [params.user_id]);
  },
  
  deleteExpired: async () => {
    const sql = `DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP`;
    return runQuery(sql);
  }
};

// Audit operations
const auditStatements = {
  create: async (params) => {
    const sql = `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent) 
                 VALUES (?, ?, ?, ?, ?, ?)`;
    return runQuery(sql, [
      params.user_id, 
      params.action, 
      params.resource_type, 
      params.resource_id, 
      params.ip_address, 
      params.user_agent
    ]);
  }
};

// Clean up expired tokens periodically
setInterval(async () => {
  try {
    const result = await tokenStatements.deleteExpired();
    if (result.changes > 0) {
      logger.info(`Cleaned up ${result.changes} expired refresh tokens`);
    }
  } catch (error) {
    logger.error('Error cleaning up expired tokens:', error);
  }
}, 60 * 60 * 1000); // Every hour

module.exports = {
  db,
  initializeDatabase,
  userStatements,
  noteStatements,
  tokenStatements,
  auditStatements
};