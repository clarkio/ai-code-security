/**
 * Input Validation and Sanitization Utility
 * Prevents XSS, SQL injection, and other injection attacks
 */
const path = require('path');
const validator = require('validator');
const config = require(path.resolve(__dirname, '../../config.json'));

class InputValidator {
  /**
   * Sanitize a string to prevent XSS attacks
   */
  static sanitizeString(input) {
    if (typeof input !== 'string') {
      return '';
    }
    // Remove null bytes and control characters
    let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    // Trim whitespace
    sanitized = validator.trim(sanitized);
    // Escape HTML entities
    sanitized = validator.escape(sanitized);
    return sanitized;
  }

  /**
   * Validate note title
   */
  static validateTitle(title) {
    const errors = [];
    
    if (!title || typeof title !== 'string') {
      errors.push('Title is required');
      return errors;
    }

    if (title.length < 1) {
      errors.push('Title cannot be empty');
    }

    if (title.length > config.security.input.maxTitleLength) {
      errors.push(`Title must be less than ${config.security.input.maxTitleLength} characters`);
    }

    // Check for dangerous patterns
    if (/<script|javascript:|data:/i.test(title)) {
      errors.push('Title contains invalid characters');
    }

    return errors;
  }

  /**
   * Validate note content
   */
  static validateContent(content) {
    const errors = [];

    if (!content || typeof content !== 'string') {
      errors.push('Content is required');
      return errors;
    }

    if (content.length > config.security.input.maxContentLength) {
      errors.push(`Content must be less than ${config.security.input.maxContentLength} characters`);
    }

    return errors;
  }

  /**
   * Validate username
   */
  static validateUsername(username) {
    const errors = [];

    if (!username || typeof username !== 'string') {
      errors.push('Username is required');
      return errors;
    }

    if (username.length < 3) {
      errors.push('Username must be at least 3 characters');
    }

    if (username.length > config.security.input.maxUsernameLength) {
      errors.push(`Username must be less than ${config.security.input.maxUsernameLength} characters`);
    }

    // Only allow alphanumeric characters and underscores
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      errors.push('Username can only contain letters, numbers, and underscores');
    }

    return errors;
  }

  /**
   * Validate password against security policy
   */
  static validatePassword(password) {
    const errors = [];
    const policy = config.security.password;

    if (!password || typeof password !== 'string') {
      errors.push('Password is required');
      return errors;
    }

    if (password.length < policy.minLength) {
      errors.push(`Password must be at least ${policy.minLength} characters`);
    }

    if (password.length > policy.maxLength) {
      errors.push(`Password must be less than ${policy.maxLength} characters`);
    }

    if (policy.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (policy.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (policy.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (policy.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // Check for common patterns
    if (/(.)\1{2,}/.test(password)) {
      errors.push('Password cannot contain more than 2 consecutive identical characters');
    }

    return errors;
  }

  /**
   * Validate UUID format
   */
  static isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }

  /**
   * Sanitize object fields
   */
  static sanitizeObject(obj, allowedFields) {
    const sanitized = {};
    for (const field of allowedFields) {
      if (obj[field] !== undefined) {
        sanitized[field] = this.sanitizeString(obj[field]);
      }
    }
    return sanitized;
  }
}

module.exports = InputValidator;
