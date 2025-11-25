/**
 * User Model
 * Handles user data with secure password hashing and parameterized queries
 */

const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcrypt");
const db = require("../database");
const logger = require("../config/logger");

// Bcrypt configuration - use high rounds for security
const BCRYPT_ROUNDS = 12;

// Account lockout configuration
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

class User {
  /**
   * Create a new user with securely hashed password
   */
  static async create(username, email, password) {
    // Hash password with bcrypt (secure against timing attacks)
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const id = uuidv4();
    const now = new Date().toISOString();

    try {
      const stmt = db.prepare(`
        INSERT INTO users (id, username, email, password_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);

      stmt.run(
        id,
        username.toLowerCase(),
        email.toLowerCase(),
        passwordHash,
        now,
        now
      );

      logger.info(`User created: ${id}`);

      return {
        id,
        username: username.toLowerCase(),
        email: email.toLowerCase(),
        createdAt: now,
      };
    } catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        if (error.message.includes("username")) {
          throw new Error("Username already exists");
        }
        if (error.message.includes("email")) {
          throw new Error("Email already exists");
        }
      }
      throw error;
    }
  }

  /**
   * Find user by ID (parameterized query)
   */
  static findById(id) {
    const stmt = db.prepare(`
      SELECT id, username, email, created_at, updated_at, last_login
      FROM users
      WHERE id = ?
    `);

    return stmt.get(id);
  }

  /**
   * Find user by username (parameterized query)
   */
  static findByUsername(username) {
    const stmt = db.prepare(`
      SELECT id, username, email, password_hash, created_at, updated_at,
             failed_login_attempts, locked_until, last_login
      FROM users
      WHERE username = ?
    `);

    return stmt.get(username.toLowerCase());
  }

  /**
   * Find user by email (parameterized query)
   */
  static findByEmail(email) {
    const stmt = db.prepare(`
      SELECT id, username, email, password_hash, created_at, updated_at,
             failed_login_attempts, locked_until, last_login
      FROM users
      WHERE email = ?
    `);

    return stmt.get(email.toLowerCase());
  }

  /**
   * Verify password with constant-time comparison (bcrypt handles this)
   */
  static async verifyPassword(plainPassword, hashedPassword) {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  /**
   * Check if account is locked
   */
  static isAccountLocked(user) {
    if (!user.locked_until) return false;

    const lockUntil = new Date(user.locked_until);
    if (lockUntil > new Date()) {
      return true;
    }

    // Lock has expired, reset it
    User.resetLoginAttempts(user.id);
    return false;
  }

  /**
   * Record failed login attempt
   */
  static recordFailedLogin(userId) {
    const stmt = db.prepare(`
      UPDATE users
      SET failed_login_attempts = failed_login_attempts + 1,
          locked_until = CASE
            WHEN failed_login_attempts + 1 >= ?
            THEN datetime('now', '+' || ? || ' minutes')
            ELSE locked_until
          END,
          updated_at = datetime('now')
      WHERE id = ?
    `);

    stmt.run(MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION_MINUTES, userId);

    logger.warn(`Failed login attempt for user: ${userId}`);
  }

  /**
   * Reset login attempts after successful login
   */
  static resetLoginAttempts(userId) {
    const stmt = db.prepare(`
      UPDATE users
      SET failed_login_attempts = 0,
          locked_until = NULL,
          last_login = datetime('now'),
          updated_at = datetime('now')
      WHERE id = ?
    `);

    stmt.run(userId);
  }

  /**
   * Update password (with re-hashing)
   */
  static async updatePassword(userId, newPassword) {
    const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

    const stmt = db.prepare(`
      UPDATE users
      SET password_hash = ?,
          updated_at = datetime('now')
      WHERE id = ?
    `);

    stmt.run(passwordHash, userId);

    logger.info(`Password updated for user: ${userId}`);
  }

  /**
   * Delete user and all associated data
   */
  static delete(userId) {
    // Foreign keys with ON DELETE CASCADE handle notes deletion
    const stmt = db.prepare("DELETE FROM users WHERE id = ?");
    const result = stmt.run(userId);

    logger.info(`User deleted: ${userId}`);

    return result.changes > 0;
  }
}

module.exports = User;
