const bcrypt = require('bcrypt');
const crypto = require('crypto');
const databaseConnection = require('../database/connection');
const encryptionService = require('../services/encryptionService');
const logger = require('../utils/logger');
const config = require('../config/environment');

class User {
  constructor(data = {}) {
    this.id = data.id;
    this.email = data.email; // Plain text email (not stored)
    this.emailEncrypted = data.email_encrypted;
    this.emailHash = data.email_hash;
    this.passwordHash = data.password_hash;
    this.isActive = data.is_active !== undefined ? data.is_active : true;
    this.failedLoginAttempts = data.failed_login_attempts || 0;
    this.lastFailedLogin = data.last_failed_login;
    this.accountLockedUntil = data.account_locked_until;
    this.createdAt = data.created_at;
    this.updatedAt = data.updated_at;
    this.lastLoginAt = data.last_login_at;
  }

  /**
   * Create a new user with encrypted email and hashed password
   */
  static async create(userData) {
    const { email, password } = userData;

    try {
      // Validate input
      await User.validateUserData({ email, password });

      // Check if user already exists
      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Encrypt email and create hash for indexing
      const emailEncrypted = encryptionService.encrypt(email.toLowerCase());
      const emailHash = User.createEmailHash(email.toLowerCase());

      // Hash password
      const passwordHash = await User.hashPassword(password);

      // Insert user into database
      const query = `
        INSERT INTO users (email_encrypted, email_hash, password_hash, is_active)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email_encrypted, email_hash, is_active, created_at, updated_at
      `;

      const result = await databaseConnection.query(query, [
        emailEncrypted,
        emailHash,
        passwordHash,
        true
      ]);

      const newUser = new User({
        ...result.rows[0],
        email: email.toLowerCase()
      });

      logger.security.dataModification({
        action: 'user_created',
        userId: newUser.id,
        resource: 'user',
        resourceId: newUser.id
      });

      return newUser;

    } catch (error) {
      logger.error('Failed to create user', {
        error: error.message,
        email: email ? '[REDACTED]' : undefined
      });
      throw error;
    }
  }

  /**
   * Find user by email
   */
  static async findByEmail(email) {
    try {
      const emailHash = User.createEmailHash(email.toLowerCase());
      
      const query = `
        SELECT id, email_encrypted, email_hash, password_hash, is_active,
               failed_login_attempts, last_failed_login, account_locked_until,
               created_at, updated_at, last_login_at
        FROM users 
        WHERE email_hash = $1 AND is_active = true
      `;

      const result = await databaseConnection.query(query, [emailHash]);

      if (result.rows.length === 0) {
        return null;
      }

      const userData = result.rows[0];
      
      // Decrypt email
      const decryptedEmail = encryptionService.decrypt(userData.email_encrypted);
      
      return new User({
        ...userData,
        email: decryptedEmail
      });

    } catch (error) {
      logger.error('Failed to find user by email', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Find user by ID
   */
  static async findById(id) {
    try {
      const query = `
        SELECT id, email_encrypted, email_hash, password_hash, is_active,
               failed_login_attempts, last_failed_login, account_locked_until,
               created_at, updated_at, last_login_at
        FROM users 
        WHERE id = $1 AND is_active = true
      `;

      const result = await databaseConnection.query(query, [id]);

      if (result.rows.length === 0) {
        return null;
      }

      const userData = result.rows[0];
      
      // Decrypt email
      const decryptedEmail = encryptionService.decrypt(userData.email_encrypted);
      
      return new User({
        ...userData,
        email: decryptedEmail
      });

    } catch (error) {
      logger.error('Failed to find user by ID', {
        error: error.message,
        userId: id
      });
      throw error;
    }
  }

  /**
   * Verify password against stored hash
   */
  async verifyPassword(password) {
    try {
      return await bcrypt.compare(password, this.passwordHash);
    } catch (error) {
      logger.error('Password verification failed', {
        error: error.message,
        userId: this.id
      });
      return false;
    }
  }

  /**
   * Update password with proper hashing
   */
  async updatePassword(newPassword) {
    try {
      // Validate new password
      User.validatePassword(newPassword);

      const passwordHash = await User.hashPassword(newPassword);

      const query = `
        UPDATE users 
        SET password_hash = $1, updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
      `;

      await databaseConnection.query(query, [passwordHash, this.id]);

      this.passwordHash = passwordHash;
      this.updatedAt = new Date();

      logger.security.dataModification({
        action: 'password_updated',
        userId: this.id,
        resource: 'user',
        resourceId: this.id
      });

    } catch (error) {
      logger.error('Failed to update password', {
        error: error.message,
        userId: this.id
      });
      throw error;
    }
  }

  /**
   * Record failed login attempt
   */
  async recordFailedLogin(ipAddress) {
    try {
      const now = new Date();
      const newFailedAttempts = this.failedLoginAttempts + 1;
      
      // Lock account if too many failed attempts
      let accountLockedUntil = null;
      if (newFailedAttempts >= 5) {
        accountLockedUntil = new Date(now.getTime() + 15 * 60 * 1000); // 15 minutes
      }

      const query = `
        UPDATE users 
        SET failed_login_attempts = $1, 
            last_failed_login = $2,
            account_locked_until = $3,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $4
      `;

      await databaseConnection.query(query, [
        newFailedAttempts,
        now,
        accountLockedUntil,
        this.id
      ]);

      this.failedLoginAttempts = newFailedAttempts;
      this.lastFailedLogin = now;
      this.accountLockedUntil = accountLockedUntil;

      logger.security.authFailure({
        userId: this.id,
        ipAddress,
        failedAttempts: newFailedAttempts,
        accountLocked: !!accountLockedUntil
      });

      if (accountLockedUntil) {
        logger.security.authLockout({
          userId: this.id,
          ipAddress,
          lockedUntil: accountLockedUntil
        });
      }

    } catch (error) {
      logger.error('Failed to record failed login', {
        error: error.message,
        userId: this.id
      });
      throw error;
    }
  }

  /**
   * Record successful login
   */
  async recordSuccessfulLogin(ipAddress) {
    try {
      const query = `
        UPDATE users 
        SET failed_login_attempts = 0,
            last_failed_login = NULL,
            account_locked_until = NULL,
            last_login_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `;

      await databaseConnection.query(query, [this.id]);

      this.failedLoginAttempts = 0;
      this.lastFailedLogin = null;
      this.accountLockedUntil = null;
      this.lastLoginAt = new Date();

      logger.security.authSuccess({
        userId: this.id,
        ipAddress
      });

    } catch (error) {
      logger.error('Failed to record successful login', {
        error: error.message,
        userId: this.id
      });
      throw error;
    }
  }

  /**
   * Check if account is currently locked
   */
  isAccountLocked() {
    if (!this.accountLockedUntil) {
      return false;
    }
    
    return new Date() < new Date(this.accountLockedUntil);
  }

  /**
   * Deactivate user account
   */
  async deactivate() {
    try {
      const query = `
        UPDATE users 
        SET is_active = false, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `;

      await databaseConnection.query(query, [this.id]);

      this.isActive = false;
      this.updatedAt = new Date();

      logger.security.dataModification({
        action: 'user_deactivated',
        userId: this.id,
        resource: 'user',
        resourceId: this.id
      });

    } catch (error) {
      logger.error('Failed to deactivate user', {
        error: error.message,
        userId: this.id
      });
      throw error;
    }
  }

  /**
   * Get user data for JSON serialization (excludes sensitive fields)
   */
  toJSON() {
    return {
      id: this.id,
      email: this.email,
      isActive: this.isActive,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      lastLoginAt: this.lastLoginAt
    };
  }

  // Static utility methods

  /**
   * Hash password using bcrypt
   */
  static async hashPassword(password) {
    try {
      return await bcrypt.hash(password, config.security.bcryptRounds);
    } catch (error) {
      logger.error('Password hashing failed', {
        error: error.message
      });
      throw new Error('Password hashing failed');
    }
  }

  /**
   * Create hash of email for indexing (allows searching without decryption)
   */
  static createEmailHash(email) {
    return crypto
      .createHash('sha256')
      .update(email.toLowerCase())
      .digest('hex');
  }

  /**
   * Validate user data
   */
  static async validateUserData(userData) {
    const { email, password } = userData;

    if (!email || typeof email !== 'string') {
      throw new Error('Valid email is required');
    }

    if (!User.isValidEmail(email)) {
      throw new Error('Invalid email format');
    }

    if (!password || typeof password !== 'string') {
      throw new Error('Password is required');
    }

    User.validatePassword(password);
  }

  /**
   * Validate email format
   */
  static isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
  }

  /**
   * Validate password complexity
   */
  static validatePassword(password) {
    if (password.length < 12) {
      throw new Error('Password must be at least 12 characters long');
    }

    if (!/[a-z]/.test(password)) {
      throw new Error('Password must contain at least one lowercase letter');
    }

    if (!/[A-Z]/.test(password)) {
      throw new Error('Password must contain at least one uppercase letter');
    }

    if (!/\d/.test(password)) {
      throw new Error('Password must contain at least one number');
    }

    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      throw new Error('Password must contain at least one special character');
    }

    // Check for common weak passwords
    const commonPasswords = [
      'password123', '123456789', 'qwerty123', 'admin123',
      'password1234', 'welcome123', 'letmein123'
    ];

    if (commonPasswords.includes(password.toLowerCase())) {
      throw new Error('Password is too common, please choose a stronger password');
    }
  }
}

module.exports = User;