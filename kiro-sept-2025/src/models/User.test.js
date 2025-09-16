const User = require('./User');
const encryptionService = require('../services/encryptionService');

// Mock dependencies
jest.mock('../database/connection');
jest.mock('../services/encryptionService');
jest.mock('../utils/logger');

const mockDb = require('../database/connection');

describe('User Model', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock encryption service
    encryptionService.encrypt.mockImplementation(text => `encrypted_${text}`);
    encryptionService.decrypt.mockImplementation(text => text.replace('encrypted_', ''));
  });

  describe('constructor', () => {
    it('should create a user instance with provided data', () => {
      const userData = {
        id: 'test-id',
        email: 'test@example.com',
        email_encrypted: 'encrypted_test@example.com',
        email_hash: 'hash123',
        password_hash: 'hashedpassword',
        is_active: true,
        failed_login_attempts: 0
      };

      const user = new User(userData);

      expect(user.id).toBe('test-id');
      expect(user.email).toBe('test@example.com');
      expect(user.emailEncrypted).toBe('encrypted_test@example.com');
      expect(user.isActive).toBe(true);
      expect(user.failedLoginAttempts).toBe(0);
    });

    it('should set default values for optional fields', () => {
      const user = new User({});

      expect(user.isActive).toBe(true);
      expect(user.failedLoginAttempts).toBe(0);
    });
  });

  describe('create', () => {
    it('should create a new user with encrypted email and hashed password', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'SecurePassword123!'
      };

      // Mock database responses
      mockDb.query
        .mockResolvedValueOnce({ rows: [] }) // findByEmail returns no existing user
        .mockResolvedValueOnce({ // create user query
          rows: [{
            id: 'new-user-id',
            email_encrypted: 'encrypted_test@example.com',
            email_hash: 'hash123',
            is_active: true,
            created_at: new Date(),
            updated_at: new Date()
          }]
        });

      const user = await User.create(userData);

      expect(user).toBeInstanceOf(User);
      expect(user.id).toBe('new-user-id');
      expect(user.email).toBe('test@example.com');
      expect(encryptionService.encrypt).toHaveBeenCalledWith('test@example.com');
    });

    it('should throw error if user already exists', async () => {
      const userData = {
        email: 'existing@example.com',
        password: 'SecurePassword123!'
      };

      // Mock existing user
      mockDb.query.mockResolvedValueOnce({
        rows: [{
          id: 'existing-id',
          email_encrypted: 'encrypted_existing@example.com'
        }]
      });

      await expect(User.create(userData)).rejects.toThrow('User with this email already exists');
    });
  });

  describe('findByEmail', () => {
    it('should find user by email and decrypt email field', async () => {
      const email = 'test@example.com';
      
      mockDb.query.mockResolvedValueOnce({
        rows: [{
          id: 'user-id',
          email_encrypted: 'encrypted_test@example.com',
          email_hash: 'hash123',
          password_hash: 'hashedpassword',
          is_active: true,
          failed_login_attempts: 0
        }]
      });

      const user = await User.findByEmail(email);

      expect(user).toBeInstanceOf(User);
      expect(user.email).toBe('test@example.com');
      expect(encryptionService.decrypt).toHaveBeenCalledWith('encrypted_test@example.com');
    });

    it('should return null if user not found', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [] });

      const user = await User.findByEmail('nonexistent@example.com');

      expect(user).toBeNull();
    });
  });

  describe('findById', () => {
    it('should find user by ID and decrypt email field', async () => {
      const userId = 'test-user-id';
      
      mockDb.query.mockResolvedValueOnce({
        rows: [{
          id: userId,
          email_encrypted: 'encrypted_test@example.com',
          email_hash: 'hash123',
          password_hash: 'hashedpassword',
          is_active: true,
          failed_login_attempts: 0
        }]
      });

      const user = await User.findById(userId);

      expect(user).toBeInstanceOf(User);
      expect(user.id).toBe(userId);
      expect(user.email).toBe('test@example.com');
    });

    it('should return null if user not found', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [] });

      const user = await User.findById('nonexistent-id');

      expect(user).toBeNull();
    });
  });

  describe('verifyPassword', () => {
    it('should verify password correctly', async () => {
      const bcrypt = require('bcrypt');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);

      const user = new User({ password_hash: 'hashedpassword' });
      const result = await user.verifyPassword('correctpassword');

      expect(result).toBe(true);
      expect(bcrypt.compare).toHaveBeenCalledWith('correctpassword', 'hashedpassword');
    });

    it('should return false for incorrect password', async () => {
      const bcrypt = require('bcrypt');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);

      const user = new User({ password_hash: 'hashedpassword' });
      const result = await user.verifyPassword('wrongpassword');

      expect(result).toBe(false);
    });
  });

  describe('recordFailedLogin', () => {
    it('should increment failed login attempts', async () => {
      const user = new User({
        id: 'user-id',
        failed_login_attempts: 2
      });

      mockDb.query.mockResolvedValueOnce({ rows: [] });

      await user.recordFailedLogin('192.168.1.1');

      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE users'),
        expect.arrayContaining([3, expect.any(Date), null, 'user-id'])
      );
    });

    it('should lock account after 5 failed attempts', async () => {
      const user = new User({
        id: 'user-id',
        failed_login_attempts: 4
      });

      mockDb.query.mockResolvedValueOnce({ rows: [] });

      await user.recordFailedLogin('192.168.1.1');

      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE users'),
        expect.arrayContaining([5, expect.any(Date), expect.any(Date), 'user-id'])
      );
    });
  });

  describe('recordSuccessfulLogin', () => {
    it('should reset failed login attempts and update last login', async () => {
      const user = new User({
        id: 'user-id',
        failed_login_attempts: 3
      });

      mockDb.query.mockResolvedValueOnce({ rows: [] });

      await user.recordSuccessfulLogin('192.168.1.1');

      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE users'),
        expect.arrayContaining(['user-id'])
      );
      expect(user.failedLoginAttempts).toBe(0);
    });
  });

  describe('isAccountLocked', () => {
    it('should return true if account is locked and lock time has not expired', () => {
      const futureTime = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
      const user = new User({
        account_locked_until: futureTime
      });

      expect(user.isAccountLocked()).toBe(true);
    });

    it('should return false if account lock has expired', () => {
      const pastTime = new Date(Date.now() - 10 * 60 * 1000); // 10 minutes ago
      const user = new User({
        account_locked_until: pastTime
      });

      expect(user.isAccountLocked()).toBe(false);
    });

    it('should return false if account is not locked', () => {
      const user = new User({
        account_locked_until: null
      });

      expect(user.isAccountLocked()).toBe(false);
    });
  });

  describe('toJSON', () => {
    it('should return safe user data without sensitive fields', () => {
      const user = new User({
        id: 'user-id',
        email: 'test@example.com',
        password_hash: 'hashedpassword',
        email_encrypted: 'encrypted_email',
        is_active: true,
        created_at: new Date(),
        updated_at: new Date()
      });

      const json = user.toJSON();

      expect(json).toHaveProperty('id');
      expect(json).toHaveProperty('email');
      expect(json).toHaveProperty('isActive');
      expect(json).not.toHaveProperty('password_hash');
      expect(json).not.toHaveProperty('email_encrypted');
      expect(json).not.toHaveProperty('emailHash');
    });
  });

  describe('validatePassword', () => {
    it('should accept valid strong password', () => {
      expect(() => {
        User.validatePassword('SecurePassword123!');
      }).not.toThrow();
    });

    it('should reject password shorter than 12 characters', () => {
      expect(() => {
        User.validatePassword('Short1!');
      }).toThrow('Password must be at least 12 characters long');
    });

    it('should reject password without lowercase letter', () => {
      expect(() => {
        User.validatePassword('UPPERCASE123!');
      }).toThrow('Password must contain at least one lowercase letter');
    });

    it('should reject password without uppercase letter', () => {
      expect(() => {
        User.validatePassword('lowercase123!');
      }).toThrow('Password must contain at least one uppercase letter');
    });

    it('should reject password without number', () => {
      expect(() => {
        User.validatePassword('NoNumbersHere!');
      }).toThrow('Password must contain at least one number');
    });

    it('should reject password without special character', () => {
      expect(() => {
        User.validatePassword('NoSpecialChars123');
      }).toThrow('Password must contain at least one special character');
    });

    it('should reject common weak passwords', () => {
      expect(() => {
        User.validatePassword('password123');
      }).toThrow('Password is too common, please choose a stronger password');
    });
  });

  describe('isValidEmail', () => {
    it('should accept valid email addresses', () => {
      const validEmails = [
        'test@example.com',
        'user.name@domain.co.uk',
        'user+tag@example.org'
      ];

      validEmails.forEach(email => {
        expect(User.isValidEmail(email)).toBe(true);
      });
    });

    it('should reject invalid email addresses', () => {
      const invalidEmails = [
        'invalid-email',
        '@example.com',
        'user@',
        'user@.com',
        'user..name@example.com'
      ];

      invalidEmails.forEach(email => {
        expect(User.isValidEmail(email)).toBe(false);
      });
    });
  });

  describe('createEmailHash', () => {
    it('should create consistent hash for same email', () => {
      const email = 'test@example.com';
      const hash1 = User.createEmailHash(email);
      const hash2 = User.createEmailHash(email);

      expect(hash1).toBe(hash2);
      expect(typeof hash1).toBe('string');
      expect(hash1.length).toBe(64); // SHA-256 hex string length
    });

    it('should create different hashes for different emails', () => {
      const hash1 = User.createEmailHash('test1@example.com');
      const hash2 = User.createEmailHash('test2@example.com');

      expect(hash1).not.toBe(hash2);
    });
  });
});