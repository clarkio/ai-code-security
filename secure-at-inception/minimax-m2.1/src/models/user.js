/**
 * User Model
 * Handles user authentication and user-related database operations
 */
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const db = require('./database');
const path = require('path');
const config = require(path.resolve(__dirname, '../../config.json'));
const logger = require('../utils/logger');

class UserModel {
  /**
   * Create a new user
   */
  static async create(username, password) {
    // Validate input
    const usernameErrors = require('../utils/validator').validateUsername(username);
    if (usernameErrors.length > 0) {
      throw new Error(usernameErrors.join(', '));
    }

    const passwordErrors = require('../utils/validator').validatePassword(password);
    if (passwordErrors.length > 0) {
      throw new Error(passwordErrors.join(', '));
    }

    // Check if username already exists
    const existingUser = db.get(
      'SELECT id FROM users WHERE username = ?',
      [username.toLowerCase()]
    );

    if (existingUser) {
      throw new Error('Username already exists');
    }

    // Hash password with secure algorithm
    const saltRounds = config.security.password.bcryptRounds;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const userId = uuidv4();
    db.run(
      `INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)`,
      [userId, username.toLowerCase(), passwordHash]
    );

    logger.securityEvent('user_created', { userId, username });

    return {
      id: userId,
      username: username.toLowerCase()
    };
  }

  /**
   * Authenticate user with username and password
   */
  static async authenticate(username, password) {
    if (!username || !password) {
      logger.securityEvent('auth_attempt_missing_credentials', { username });
      throw new Error('Invalid credentials');
    }

    const user = db.get(
      'SELECT * FROM users WHERE username = ?',
      [username.toLowerCase()]
    );

    if (!user) {
      logger.securityEvent('auth_attempt_nonexistent_user', { username });
      throw new Error('Invalid credentials');
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      logger.securityEvent('auth_attempt_locked_account', { userId: user.id });
      throw new Error('Account is temporarily locked');
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password_hash);

    if (!passwordValid) {
      // Increment failed attempts
      const failedAttempts = (user.failed_login_attempts || 0) + 1;
      let lockedUntil = null;

      // Lock account after 5 failed attempts for 30 minutes
      if (failedAttempts >= 5) {
        lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        logger.securityEvent('account_locked', { userId: user.id, failedAttempts });
      }

      db.run(
        `UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP 
         WHERE id = ?`,
        [failedAttempts, lockedUntil, user.id]
      );

      logger.securityEvent('auth_failure', { userId: user.id, failedAttempts });
      throw new Error('Invalid credentials');
    }

    // Reset failed attempts on successful login
    db.run(
      `UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP, 
       updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [user.id]
    );

    logger.securityEvent('auth_success', { userId: user.id });

    return {
      id: user.id,
      username: user.username
    };
  }

  /**
   * Get user by ID
   */
  static getById(id) {
    return db.get('SELECT id, username, created_at, last_login FROM users WHERE id = ?', [id]);
  }

  /**
   * Get user by username
   */
  static getByUsername(username) {
    return db.get('SELECT * FROM users WHERE username = ?', [username.toLowerCase()]);
  }
}

module.exports = UserModel;
