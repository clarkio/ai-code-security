const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const config = require('../config/environment');
const logger = require('../utils/logger');
const encryptionService = require('./encryptionService');

class AuthService {
  constructor() {
    this.maxFailedAttempts = 5;
    this.lockoutDuration = 15 * 60 * 1000; // 15 minutes in milliseconds
    this.jwtExpiry = '15m';
    this.refreshTokenExpiry = '7d';
  }

  /**
   * Register a new user with secure validation and encryption
   */
  async register(userData) {
    const { email, password, confirmPassword } = userData;

    try {
      // Input validation and sanitization
      this.validateRegistrationInput({ email, password, confirmPassword });

      // Sanitize email
      const sanitizedEmail = this.sanitizeEmail(email);

      // Additional password complexity validation
      this.validatePasswordComplexity(password);

      // Check password confirmation
      if (password !== confirmPassword) {
        throw new Error('Password confirmation does not match');
      }

      // Create user with encrypted email and hashed password
      const user = await User.create({
        email: sanitizedEmail,
        password: password
      });

      // Log successful registration (without sensitive data)
      logger.security.authSuccess({
        action: 'user_registration',
        userId: user.id,
        email: '[REDACTED]'
      });

      // Return user data without sensitive information
      return {
        id: user.id,
        email: user.email,
        isActive: user.isActive,
        createdAt: user.createdAt
      };

    } catch (error) {
      // Log registration failure
      logger.security.authFailure({
        action: 'user_registration',
        error: error.message,
        email: email ? '[REDACTED]' : undefined
      });

      // Re-throw with appropriate error message
      if (error.message.includes('already exists')) {
        throw new Error('An account with this email already exists');
      }

      if (this.isValidationError(error)) {
        throw error;
      }

      throw new Error('Registration failed. Please try again.');
    }
  }

  /**
   * Validate registration input data
   */
  validateRegistrationInput({ email, password, confirmPassword }) {
    // Email validation
    if (!email || typeof email !== 'string') {
      throw new Error('Email is required');
    }

    if (email.length > 254) {
      throw new Error('Email address is too long');
    }

    // Additional security checks first
    if (email.includes('<') || email.includes('>') || email.includes('"')) {
      throw new Error('Email contains invalid characters');
    }

    if (!this.isValidEmail(email)) {
      throw new Error('Please enter a valid email address');
    }

    // Password validation
    if (!password || typeof password !== 'string') {
      throw new Error('Password is required');
    }

    if (!confirmPassword || typeof confirmPassword !== 'string') {
      throw new Error('Password confirmation is required');
    }
  }

  /**
   * Validate password complexity with detailed error messages
   */
  validatePasswordComplexity(password) {
    const errors = [];

    if (password.length < 12) {
      errors.push('Password must be at least 12 characters long');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter (a-z)');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter (A-Z)');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number (0-9)');
    }

    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)');
    }

    // Check for common weak passwords
    const commonPasswords = [
      'password123', '123456789', 'qwerty123', 'admin123',
      'password1234', 'welcome123', 'letmein123', 'password12',
      '123456789012', 'qwertyuiop12', 'administrator'
    ];

    if (commonPasswords.some(common => password.toLowerCase().includes(common))) {
      errors.push('Password contains common patterns that are easily guessed');
    }

    // Check for sequential characters
    if (this.hasSequentialCharacters(password)) {
      errors.push('Password should not contain sequential characters (e.g., 123, abc)');
    }

    // Check for repeated characters
    if (this.hasRepeatedCharacters(password)) {
      errors.push('Password should not contain excessive repeated characters');
    }

    if (errors.length > 0) {
      throw new Error(`Password requirements not met:\n• ${errors.join('\n• ')}`);
    }
  }

  /**
   * Check for sequential characters in password
   */
  hasSequentialCharacters(password) {
    const sequences = [
      '123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
    ];

    return sequences.some(seq => {
      for (let i = 0; i <= seq.length - 3; i++) {
        const subseq = seq.substring(i, i + 3);
        if (password.toLowerCase().includes(subseq) || 
            password.toLowerCase().includes(subseq.split('').reverse().join(''))) {
          return true;
        }
      }
      return false;
    });
  }

  /**
   * Check for excessive repeated characters
   */
  hasRepeatedCharacters(password) {
    // Check for 3 or more consecutive identical characters
    return /(.)\1{2,}/.test(password);
  }

  /**
   * Validate email format
   */
  isValidEmail(email) {
    // More strict email validation
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
    
    // Additional checks for invalid patterns
    if (email.includes('..')) return false; // No consecutive dots
    if (!email.includes('.')) return false; // Must have at least one dot after @
    if (email.split('@').length !== 2) return false; // Exactly one @
    
    const [localPart, domainPart] = email.split('@');
    if (!localPart || !domainPart) return false;
    if (!domainPart.includes('.')) return false; // Domain must have extension
    
    return emailRegex.test(email);
  }

  /**
   * Sanitize email input
   */
  sanitizeEmail(email) {
    return email.toLowerCase().trim();
  }

  /**
   * Check if error is a validation error
   */
  isValidationError(error) {
    const validationMessages = [
      'Email is required',
      'Password is required',
      'Password confirmation is required',
      'Please enter a valid email address',
      'Password requirements not met',
      'Password confirmation does not match',
      'Email contains invalid characters',
      'Email address is too long',
      'An account with this email already exists'
    ];

    return validationMessages.some(msg => error.message.includes(msg));
  }

  /**
   * Generate secure random token
   */
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Hash password with bcrypt
   */
  async hashPassword(password) {
    try {
      const saltRounds = config.security.bcryptRounds || 12;
      return await bcrypt.hash(password, saltRounds);
    } catch (error) {
      logger.error('Password hashing failed', {
        error: error.message
      });
      throw new Error('Password processing failed');
    }
  }

  /**
   * Verify password against hash
   */
  async verifyPassword(password, hash) {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error('Password verification failed', {
        error: error.message
      });
      return false;
    }
  }

  /**
   * Create timing-safe password verification to prevent timing attacks
   */
  async timingSafePasswordVerify(password, hash) {
    try {
      // Always perform bcrypt operation to maintain consistent timing
      const isValid = await bcrypt.compare(password, hash);
      
      // Add small random delay to further obscure timing
      const delay = Math.floor(Math.random() * 10) + 5;
      await new Promise(resolve => setTimeout(resolve, delay));
      
      return isValid;
    } catch (error) {
      // Still add delay even on error to maintain timing consistency
      const delay = Math.floor(Math.random() * 10) + 5;
      await new Promise(resolve => setTimeout(resolve, delay));
      
      logger.error('Timing-safe password verification failed', {
        error: error.message
      });
      return false;
    }
  }

  /**
   * Authenticate user login with timing attack protection
   */
  async login(credentials, ipAddress) {
    const { email, password } = credentials;

    try {
      // Input validation
      this.validateLoginInput({ email, password });

      // Sanitize email
      const sanitizedEmail = this.sanitizeEmail(email);

      // Check rate limiting
      await this.checkRateLimit(ipAddress, sanitizedEmail);

      // Find user by email
      const user = await User.findByEmail(sanitizedEmail);

      // Always perform password verification to prevent timing attacks
      const isValidPassword = user ? 
        await this.timingSafePasswordVerify(password, user.passwordHash) : 
        await this.timingSafePasswordVerify(password, '$2b$12$dummy.hash.to.prevent.timing.attacks');

      // Check if user exists and password is valid
      if (!user || !isValidPassword) {
        // Record failed attempt for rate limiting
        await this.recordFailedLoginAttempt(ipAddress, sanitizedEmail);
        
        if (user) {
          await user.recordFailedLogin(ipAddress);
        }

        throw new Error('Invalid email or password');
      }

      // Check if account is locked
      if (user.isAccountLocked()) {
        await this.recordFailedLoginAttempt(ipAddress, sanitizedEmail);
        throw new Error('Account is temporarily locked due to too many failed login attempts');
      }

      // Generate JWT tokens
      const tokens = await this.generateTokens(user);

      // Record successful login
      await user.recordSuccessfulLogin(ipAddress);
      await this.clearRateLimitCounters(ipAddress, sanitizedEmail);

      // Log successful login
      logger.security.authSuccess({
        action: 'user_login',
        userId: user.id,
        ipAddress,
        email: '[REDACTED]'
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          isActive: user.isActive,
          lastLoginAt: user.lastLoginAt
        },
        tokens
      };

    } catch (error) {
      // Log login failure
      logger.security.authFailure({
        action: 'user_login',
        error: error.message,
        ipAddress,
        email: email ? '[REDACTED]' : undefined
      });

      // Re-throw validation and authentication errors
      if (this.isAuthenticationError(error)) {
        throw error;
      }

      throw new Error('Login failed. Please try again.');
    }
  }

  /**
   * Validate login input
   */
  validateLoginInput({ email, password }) {
    if (!email || typeof email !== 'string') {
      throw new Error('Email is required');
    }

    if (!password || typeof password !== 'string') {
      throw new Error('Password is required');
    }

    if (!this.isValidEmail(email)) {
      throw new Error('Please enter a valid email address');
    }
  }

  /**
   * Check rate limiting for IP address and user account
   */
  async checkRateLimit(ipAddress, email) {
    // Check IP-based rate limiting (10 attempts per 15 minutes)
    const ipKey = `rate_limit:ip:${ipAddress}`;
    const ipAttempts = await this.getRateLimitCount(ipKey);
    
    if (ipAttempts >= 10) {
      throw new Error('Too many login attempts from this IP address. Please try again later.');
    }

    // Check user-based rate limiting (5 attempts per 15 minutes)
    const userKey = `rate_limit:user:${this.hashEmail(email)}`;
    const userAttempts = await this.getRateLimitCount(userKey);
    
    if (userAttempts >= 5) {
      throw new Error('Too many login attempts for this account. Please try again later.');
    }
  }

  /**
   * Record failed login attempt for rate limiting
   */
  async recordFailedLoginAttempt(ipAddress, email) {
    const ipKey = `rate_limit:ip:${ipAddress}`;
    const userKey = `rate_limit:user:${this.hashEmail(email)}`;
    
    await Promise.all([
      this.incrementRateLimitCount(ipKey),
      this.incrementRateLimitCount(userKey)
    ]);
  }

  /**
   * Clear rate limit counters on successful login
   */
  async clearRateLimitCounters(ipAddress, email) {
    const ipKey = `rate_limit:ip:${ipAddress}`;
    const userKey = `rate_limit:user:${this.hashEmail(email)}`;
    
    await Promise.all([
      this.clearRateLimitCount(ipKey),
      this.clearRateLimitCount(userKey)
    ]);
  }

  /**
   * Get rate limit count (mock implementation - would use Redis in production)
   */
  async getRateLimitCount(key) {
    // In a real implementation, this would use Redis
    // For now, we'll use a simple in-memory store
    if (!this.rateLimitStore) {
      this.rateLimitStore = new Map();
    }

    const entry = this.rateLimitStore.get(key);
    if (!entry) return 0;

    // Check if entry has expired (15 minutes)
    if (Date.now() - entry.timestamp > 15 * 60 * 1000) {
      this.rateLimitStore.delete(key);
      return 0;
    }

    return entry.count;
  }

  /**
   * Increment rate limit count
   */
  async incrementRateLimitCount(key) {
    if (!this.rateLimitStore) {
      this.rateLimitStore = new Map();
    }

    const entry = this.rateLimitStore.get(key) || { count: 0, timestamp: Date.now() };
    
    // Reset if expired
    if (Date.now() - entry.timestamp > 15 * 60 * 1000) {
      entry.count = 0;
      entry.timestamp = Date.now();
    }

    entry.count++;
    this.rateLimitStore.set(key, entry);
  }

  /**
   * Clear rate limit count
   */
  async clearRateLimitCount(key) {
    if (this.rateLimitStore) {
      this.rateLimitStore.delete(key);
    }
  }

  /**
   * Generate JWT access and refresh tokens
   */
  async generateTokens(user) {
    try {
      const payload = {
        userId: user.id,
        email: user.email,
        type: 'access'
      };

      const refreshPayload = {
        userId: user.id,
        email: user.email,
        type: 'refresh',
        tokenId: this.generateSecureToken(16) // Unique token ID for rotation
      };

      const accessToken = jwt.sign(payload, config.jwt.secret, {
        expiresIn: this.jwtExpiry,
        issuer: config.jwt.issuer || 'secure-notes-app',
        audience: config.jwt.audience || 'secure-notes-users'
      });

      const refreshToken = jwt.sign(refreshPayload, config.jwt.refreshSecret, {
        expiresIn: this.refreshTokenExpiry,
        issuer: config.jwt.issuer || 'secure-notes-app',
        audience: config.jwt.audience || 'secure-notes-users'
      });

      // Store refresh token for validation (would use Redis in production)
      await this.storeRefreshToken(user.id, refreshPayload.tokenId, refreshToken);

      return {
        accessToken,
        refreshToken,
        expiresIn: 15 * 60, // 15 minutes in seconds
        tokenType: 'Bearer'
      };

    } catch (error) {
      logger.error('Token generation failed', {
        error: error.message,
        userId: user.id
      });
      throw new Error('Token generation failed');
    }
  }

  /**
   * Store refresh token (mock implementation - would use Redis in production)
   */
  async storeRefreshToken(userId, tokenId, refreshToken) {
    if (!this.refreshTokenStore) {
      this.refreshTokenStore = new Map();
    }

    const key = `refresh_token:${userId}:${tokenId}`;
    this.refreshTokenStore.set(key, {
      token: refreshToken,
      createdAt: Date.now(),
      userId
    });
  }

  /**
   * Hash email for rate limiting keys
   */
  hashEmail(email) {
    return crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');
  }

  /**
   * Check if error is an authentication error
   */
  isAuthenticationError(error) {
    const authMessages = [
      'Email is required',
      'Password is required',
      'Please enter a valid email address',
      'Invalid email or password',
      'Account is temporarily locked',
      'Too many login attempts'
    ];

    return authMessages.some(msg => error.message.includes(msg));
  }

  /**
   * Validate JWT access token
   */
  async validateAccessToken(token) {
    try {
      if (!token || typeof token !== 'string') {
        throw new Error('Token is required');
      }

      // Remove Bearer prefix if present
      const cleanToken = token.startsWith('Bearer ') ? token.slice(7) : token;

      // Check if token is blacklisted
      if (await this.isTokenBlacklisted(cleanToken)) {
        throw new Error('Token has been revoked');
      }

      // Verify JWT token
      const decoded = jwt.verify(cleanToken, config.jwt.secret, {
        issuer: config.jwt.issuer || 'secure-notes-app',
        audience: config.jwt.audience || 'secure-notes-users'
      });

      // Validate token type
      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      // Verify user still exists and is active
      const user = await User.findById(decoded.userId);
      if (!user || !user.isActive) {
        throw new Error('User not found or inactive');
      }

      return {
        userId: decoded.userId,
        email: decoded.email,
        user: user
      };

    } catch (error) {
      logger.security.authFailure({
        action: 'token_validation',
        error: error.message,
        token: token ? '[REDACTED]' : undefined
      });

      if (error.name === 'TokenExpiredError') {
        throw new Error('Token has expired');
      }

      if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token');
      }

      throw error;
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(refreshToken) {
    try {
      if (!refreshToken || typeof refreshToken !== 'string') {
        throw new Error('Refresh token is required');
      }

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret, {
        issuer: config.jwt.issuer || 'secure-notes-app',
        audience: config.jwt.audience || 'secure-notes-users'
      });

      // Validate token type
      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      // Check if refresh token exists in store
      const storedToken = await this.getStoredRefreshToken(decoded.userId, decoded.tokenId);
      if (!storedToken || storedToken.token !== refreshToken) {
        throw new Error('Refresh token not found or invalid');
      }

      // Verify user still exists and is active
      const user = await User.findById(decoded.userId);
      if (!user || !user.isActive) {
        throw new Error('User not found or inactive');
      }

      // Generate new access token
      const newAccessToken = jwt.sign({
        userId: user.id,
        email: user.email,
        type: 'access'
      }, config.jwt.secret, {
        expiresIn: this.jwtExpiry,
        issuer: config.jwt.issuer || 'secure-notes-app',
        audience: config.jwt.audience || 'secure-notes-users'
      });

      // Generate new refresh token with rotation
      const newRefreshPayload = {
        userId: user.id,
        email: user.email,
        type: 'refresh',
        tokenId: this.generateSecureToken(16)
      };

      const newRefreshToken = jwt.sign(newRefreshPayload, config.jwt.refreshSecret, {
        expiresIn: this.refreshTokenExpiry,
        issuer: config.jwt.issuer || 'secure-notes-app',
        audience: config.jwt.audience || 'secure-notes-users'
      });

      // Remove old refresh token and store new one
      await this.removeStoredRefreshToken(decoded.userId, decoded.tokenId);
      await this.storeRefreshToken(user.id, newRefreshPayload.tokenId, newRefreshToken);

      logger.security.authSuccess({
        action: 'token_refresh',
        userId: user.id,
        email: '[REDACTED]'
      });

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: 15 * 60, // 15 minutes in seconds
        tokenType: 'Bearer'
      };

    } catch (error) {
      logger.security.authFailure({
        action: 'token_refresh',
        error: error.message,
        refreshToken: refreshToken ? '[REDACTED]' : undefined
      });

      if (error.name === 'TokenExpiredError') {
        throw new Error('Refresh token has expired');
      }

      if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid refresh token');
      }

      throw error;
    }
  }

  /**
   * Logout user and invalidate tokens
   */
  async logout(accessToken, refreshToken) {
    try {
      let userId = null;

      // Extract user ID from access token if available
      if (accessToken) {
        try {
          const cleanToken = accessToken.startsWith('Bearer ') ? accessToken.slice(7) : accessToken;
          const decoded = jwt.decode(cleanToken);
          userId = decoded?.userId;
        } catch (error) {
          // Token might be invalid, but we still want to proceed with logout
        }
      }

      // Blacklist access token
      if (accessToken) {
        await this.blacklistToken(accessToken);
      }

      // Remove refresh token from store
      if (refreshToken && userId) {
        try {
          const decoded = jwt.decode(refreshToken);
          if (decoded?.tokenId) {
            await this.removeStoredRefreshToken(userId, decoded.tokenId);
          }
        } catch (error) {
          // Token might be invalid, but we still want to proceed
        }
      }

      logger.security.authSuccess({
        action: 'user_logout',
        userId: userId || 'unknown',
        message: 'User logged out successfully'
      });

      return { success: true, message: 'Logged out successfully' };

    } catch (error) {
      logger.error('Logout failed', {
        error: error.message,
        userId: userId || 'unknown'
      });

      // Don't throw error on logout - always succeed
      return { success: true, message: 'Logged out successfully' };
    }
  }

  /**
   * Check if token is blacklisted (mock implementation - would use Redis in production)
   */
  async isTokenBlacklisted(token) {
    if (!this.tokenBlacklist) {
      this.tokenBlacklist = new Set();
    }

    return this.tokenBlacklist.has(token);
  }

  /**
   * Blacklist a token
   */
  async blacklistToken(token) {
    if (!this.tokenBlacklist) {
      this.tokenBlacklist = new Set();
    }

    const cleanToken = token.startsWith('Bearer ') ? token.slice(7) : token;
    this.tokenBlacklist.add(cleanToken);

    // In production, you would also set an expiration time in Redis
    // matching the token's expiration time
  }

  /**
   * Get stored refresh token
   */
  async getStoredRefreshToken(userId, tokenId) {
    if (!this.refreshTokenStore) {
      return null;
    }

    const key = `refresh_token:${userId}:${tokenId}`;
    return this.refreshTokenStore.get(key) || null;
  }

  /**
   * Remove stored refresh token
   */
  async removeStoredRefreshToken(userId, tokenId) {
    if (!this.refreshTokenStore) {
      return;
    }

    const key = `refresh_token:${userId}:${tokenId}`;
    this.refreshTokenStore.delete(key);
  }

  /**
   * Clean up expired refresh tokens (should be run periodically)
   */
  async cleanupExpiredTokens() {
    if (!this.refreshTokenStore) {
      return { cleaned: 0 };
    }

    let cleaned = 0;
    const now = Date.now();
    const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

    for (const [key, tokenData] of this.refreshTokenStore.entries()) {
      if (now - tokenData.createdAt > maxAge) {
        this.refreshTokenStore.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.info('Cleaned up expired refresh tokens', { cleaned });
    }

    return { cleaned };
  }

  /**
   * Validate session and return user info
   */
  async validateSession(token) {
    try {
      const validation = await this.validateAccessToken(token);
      
      return {
        valid: true,
        user: {
          id: validation.user.id,
          email: validation.user.email,
          isActive: validation.user.isActive,
          lastLoginAt: validation.user.lastLoginAt
        }
      };

    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }

  /**
   * Create JWT middleware for Express
   */
  createAuthMiddleware() {
    return async (req, res, next) => {
      try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
          return res.status(401).json({
            error: 'Authorization header required',
            code: 'MISSING_TOKEN'
          });
        }

        const validation = await this.validateAccessToken(authHeader);
        
        // Add user info to request
        req.user = validation.user;
        req.userId = validation.userId;
        
        next();

      } catch (error) {
        let statusCode = 401;
        let errorCode = 'INVALID_TOKEN';

        if (error.message.includes('expired')) {
          errorCode = 'TOKEN_EXPIRED';
        } else if (error.message.includes('revoked')) {
          errorCode = 'TOKEN_REVOKED';
        }

        return res.status(statusCode).json({
          error: error.message,
          code: errorCode
        });
      }
    };
  }

  /**
   * Get service status
   */
  getStatus() {
    return {
      maxFailedAttempts: this.maxFailedAttempts,
      lockoutDuration: this.lockoutDuration,
      jwtExpiry: this.jwtExpiry,
      refreshTokenExpiry: this.refreshTokenExpiry,
      bcryptRounds: config.security.bcryptRounds || 12,
      rateLimitStore: this.rateLimitStore ? this.rateLimitStore.size : 0,
      refreshTokenStore: this.refreshTokenStore ? this.refreshTokenStore.size : 0,
      tokenBlacklist: this.tokenBlacklist ? this.tokenBlacklist.size : 0
    };
  }
}

// Create singleton instance
const authService = new AuthService();

module.exports = authService;