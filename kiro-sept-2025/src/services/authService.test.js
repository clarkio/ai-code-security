// Mock dependencies before requiring modules
jest.mock('../models/User');
jest.mock('../utils/logger');
jest.mock('../config/environment', () => ({
  security: {
    bcryptRounds: 12
  },
  logging: {
    level: 'info'
  },
  app: {
    env: 'test'
  },
  encryption: {
    key: 'dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcw==',
    rotationKey: null
  },
  jwt: {
    secret: 'test-jwt-secret-key-for-testing-purposes',
    refreshSecret: 'test-jwt-refresh-secret-key-for-testing',
    issuer: 'secure-notes-app',
    audience: 'secure-notes-users'
  }
}));
jest.mock('../database/connection', () => ({
  query: jest.fn()
}));
jest.mock('./encryptionService', () => ({
  encrypt: jest.fn(),
  decrypt: jest.fn()
}));

const authService = require('./authService');
const User = require('../models/User');
const logger = require('../utils/logger');

describe('AuthService - User Registration Security', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock logger methods
    logger.security = {
      authSuccess: jest.fn(),
      authFailure: jest.fn()
    };
    logger.error = jest.fn();
  });

  describe('register()', () => {
    const validUserData = {
      email: 'test@example.com',
      password: 'SecureP@ssw0rd!',
      confirmPassword: 'SecureP@ssw0rd!'
    };

    it('should successfully register a user with valid data', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true,
        createdAt: new Date()
      };

      User.create.mockResolvedValue(mockUser);

      const result = await authService.register(validUserData);

      expect(result).toEqual({
        id: 'user-123',
        email: 'test@example.com',
        isActive: true,
        createdAt: mockUser.createdAt
      });

      expect(User.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'SecureP@ssw0rd!'
      });

      expect(logger.security.authSuccess).toHaveBeenCalledWith({
        action: 'user_registration',
        userId: 'user-123',
        email: '[REDACTED]'
      });
    });

    it('should handle existing user error gracefully', async () => {
      User.create.mockRejectedValue(new Error('User with this email already exists'));

      await expect(authService.register(validUserData))
        .rejects.toThrow('An account with this email already exists');

      expect(logger.security.authFailure).toHaveBeenCalledWith({
        action: 'user_registration',
        error: 'User with this email already exists',
        email: '[REDACTED]'
      });
    });

    it('should handle database errors gracefully', async () => {
      User.create.mockRejectedValue(new Error('Database connection failed'));

      await expect(authService.register(validUserData))
        .rejects.toThrow('Registration failed. Please try again.');

      expect(logger.security.authFailure).toHaveBeenCalled();
    });
  });

  describe('validateRegistrationInput()', () => {
    it('should reject missing email', () => {
      expect(() => {
        authService.validateRegistrationInput({
          email: '',
          password: 'SecureP@ssw0rd!',
          confirmPassword: 'SecureP@ssw0rd!'
        });
      }).toThrow('Email is required');
    });

    it('should reject invalid email format', () => {
      expect(() => {
        authService.validateRegistrationInput({
          email: 'invalid-email',
          password: 'SecureP@ssw0rd!',
          confirmPassword: 'SecureP@ssw0rd!'
        });
      }).toThrow('Please enter a valid email address');
    });

    it('should reject email with dangerous characters', () => {
      expect(() => {
        authService.validateRegistrationInput({
          email: 'test<script>@example.com',
          password: 'SecureP@ssw0rd!',
          confirmPassword: 'SecureP@ssw0rd!'
        });
      }).toThrow('Email contains invalid characters');
    });

    it('should reject overly long email', () => {
      const longEmail = 'a'.repeat(250) + '@example.com';
      expect(() => {
        authService.validateRegistrationInput({
          email: longEmail,
          password: 'SecureP@ssw0rd!',
          confirmPassword: 'SecureP@ssw0rd!'
        });
      }).toThrow('Email address is too long');
    });

    it('should reject missing password', () => {
      expect(() => {
        authService.validateRegistrationInput({
          email: 'test@example.com',
          password: '',
          confirmPassword: 'SecureP@ssw0rd!'
        });
      }).toThrow('Password is required');
    });

    it('should reject missing password confirmation', () => {
      expect(() => {
        authService.validateRegistrationInput({
          email: 'test@example.com',
          password: 'SecureP@ssw0rd!',
          confirmPassword: ''
        });
      }).toThrow('Password confirmation is required');
    });
  });

  describe('validatePasswordComplexity()', () => {
    it('should accept strong password', () => {
      expect(() => {
        authService.validatePasswordComplexity('SecureP@ssw0rd!');
      }).not.toThrow();
    });

    it('should reject password shorter than 12 characters', () => {
      expect(() => {
        authService.validatePasswordComplexity('Short1!');
      }).toThrow('Password must be at least 12 characters long');
    });

    it('should reject password without lowercase letters', () => {
      expect(() => {
        authService.validatePasswordComplexity('SECUREPASS123!');
      }).toThrow('Password must contain at least one lowercase letter (a-z)');
    });

    it('should reject password without uppercase letters', () => {
      expect(() => {
        authService.validatePasswordComplexity('securepass123!');
      }).toThrow('Password must contain at least one uppercase letter (A-Z)');
    });

    it('should reject password without numbers', () => {
      expect(() => {
        authService.validatePasswordComplexity('SecurePassword!');
      }).toThrow('Password must contain at least one number (0-9)');
    });

    it('should reject password without special characters', () => {
      expect(() => {
        authService.validatePasswordComplexity('SecurePass123');
      }).toThrow('Password must contain at least one special character');
    });

    it('should reject common weak passwords', () => {
      expect(() => {
        authService.validatePasswordComplexity('Password123!');
      }).toThrow('Password contains common patterns that are easily guessed');
    });

    it('should reject passwords with sequential characters', () => {
      expect(() => {
        authService.validatePasswordComplexity('SecureAbc123!');
      }).toThrow('Password should not contain sequential characters');
    });

    it('should reject passwords with repeated characters', () => {
      expect(() => {
        authService.validatePasswordComplexity('SecureAAA123!');
      }).toThrow('Password should not contain excessive repeated characters');
    });

    it('should provide detailed error messages for multiple violations', () => {
      expect(() => {
        authService.validatePasswordComplexity('weak');
      }).toThrow(/Password requirements not met:/);
    });
  });

  describe('Password confirmation validation', () => {
    it('should reject mismatched passwords', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'SecureP@ssw0rd!',
        confirmPassword: 'DifferentP@ssw0rd!'
      };

      await expect(authService.register(userData))
        .rejects.toThrow('Password confirmation does not match');
    });

    it('should accept matching passwords', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'SecureP@ssw0rd!',
        confirmPassword: 'SecureP@ssw0rd!'
      };

      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true,
        createdAt: new Date()
      };

      User.create.mockResolvedValue(mockUser);

      const result = await authService.register(userData);
      expect(result.id).toBe('user-123');
    });
  });

  describe('Email sanitization', () => {
    it('should convert email to lowercase', () => {
      const sanitized = authService.sanitizeEmail('TEST@EXAMPLE.COM');
      expect(sanitized).toBe('test@example.com');
    });

    it('should trim whitespace from email', () => {
      const sanitized = authService.sanitizeEmail('  test@example.com  ');
      expect(sanitized).toBe('test@example.com');
    });

    it('should handle mixed case and whitespace', () => {
      const sanitized = authService.sanitizeEmail('  TeSt@ExAmPlE.CoM  ');
      expect(sanitized).toBe('test@example.com');
    });
  });

  describe('isValidEmail()', () => {
    const validEmails = [
      'test@example.com',
      'user.name@example.com',
      'user+tag@example.com',
      'user123@example-domain.com',
      'a@b.co'
    ];

    const invalidEmails = [
      'invalid-email',
      '@example.com',
      'test@',
      'test..test@example.com',
      'test@example',
      'test@.example.com',
      'test@example..com',
      ''
    ];

    validEmails.forEach(email => {
      it(`should accept valid email: ${email}`, () => {
        expect(authService.isValidEmail(email)).toBe(true);
      });
    });

    invalidEmails.forEach(email => {
      it(`should reject invalid email: ${email}`, () => {
        expect(authService.isValidEmail(email)).toBe(false);
      });
    });
  });

  describe('hasSequentialCharacters()', () => {
    it('should detect numeric sequences', () => {
      expect(authService.hasSequentialCharacters('Pass123word')).toBe(true);
      expect(authService.hasSequentialCharacters('Pass321word')).toBe(true);
    });

    it('should detect alphabetic sequences', () => {
      expect(authService.hasSequentialCharacters('Passabcword')).toBe(true);
      expect(authService.hasSequentialCharacters('Passcbaword')).toBe(true);
    });

    it('should detect keyboard sequences', () => {
      expect(authService.hasSequentialCharacters('Passqweword')).toBe(true);
      expect(authService.hasSequentialCharacters('Passasdword')).toBe(true);
    });

    it('should not flag non-sequential characters', () => {
      expect(authService.hasSequentialCharacters('SecurePass!')).toBe(false);
    });
  });

  describe('hasRepeatedCharacters()', () => {
    it('should detect 3 or more repeated characters', () => {
      expect(authService.hasRepeatedCharacters('Passaaword')).toBe(false); // Only 2 'a's
      expect(authService.hasRepeatedCharacters('Passaaaword')).toBe(true); // 3 'a's
      expect(authService.hasRepeatedCharacters('Pass111word')).toBe(true); // 3 '1's
    });

    it('should not flag non-repeated characters', () => {
      expect(authService.hasRepeatedCharacters('SecurePass!')).toBe(false);
    });
  });

  describe('Security logging', () => {
    it('should log successful registration without exposing email', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true,
        createdAt: new Date()
      };

      User.create.mockResolvedValue(mockUser);

      await authService.register({
        email: 'test@example.com',
        password: 'SecureP@ssw0rd!',
        confirmPassword: 'SecureP@ssw0rd!'
      });

      expect(logger.security.authSuccess).toHaveBeenCalledWith({
        action: 'user_registration',
        userId: 'user-123',
        email: '[REDACTED]'
      });
    });

    it('should log failed registration without exposing email', async () => {
      User.create.mockRejectedValue(new Error('Database error'));

      await expect(authService.register({
        email: 'test@example.com',
        password: 'SecureP@ssw0rd!',
        confirmPassword: 'SecureP@ssw0rd!'
      })).rejects.toThrow();

      expect(logger.security.authFailure).toHaveBeenCalledWith({
        action: 'user_registration',
        error: 'Database error',
        email: '[REDACTED]'
      });
    });
  });

  describe('Error handling', () => {
    it('should identify validation errors correctly', () => {
      const validationError = new Error('Email is required');
      const dbError = new Error('Connection failed');

      expect(authService.isValidationError(validationError)).toBe(true);
      expect(authService.isValidationError(dbError)).toBe(false);
    });

    it('should preserve validation error messages', async () => {
      await expect(authService.register({
        email: '',
        password: 'SecureP@ssw0rd!',
        confirmPassword: 'SecureP@ssw0rd!'
      })).rejects.toThrow('Email is required');
    });

    it('should mask non-validation errors', async () => {
      User.create.mockRejectedValue(new Error('Internal database error'));

      await expect(authService.register({
        email: 'test@example.com',
        password: 'SecureP@ssw0rd!',
        confirmPassword: 'SecureP@ssw0rd!'
      })).rejects.toThrow('Registration failed. Please try again.');
    });
  });

  describe('Timing-safe operations', () => {
    it('should provide timing-safe password verification', async () => {
      const password = 'SecurePass123!';
      const hash = '$2b$12$test.hash.value';

      // Mock bcrypt.compare
      const bcrypt = require('bcrypt');
      bcrypt.compare = jest.fn().mockResolvedValue(true);

      const startTime = Date.now();
      const result = await authService.timingSafePasswordVerify(password, hash);
      const endTime = Date.now();

      expect(result).toBe(true);
      expect(endTime - startTime).toBeGreaterThanOrEqual(5); // Should have delay
      expect(bcrypt.compare).toHaveBeenCalledWith(password, hash);
    });

    it('should maintain consistent timing on verification failure', async () => {
      const password = 'WrongPassword';
      const hash = '$2b$12$test.hash.value';

      const bcrypt = require('bcrypt');
      bcrypt.compare = jest.fn().mockResolvedValue(false);

      const startTime = Date.now();
      const result = await authService.timingSafePasswordVerify(password, hash);
      const endTime = Date.now();

      expect(result).toBe(false);
      expect(endTime - startTime).toBeGreaterThanOrEqual(5); // Should have delay
    });

    it('should maintain consistent timing on verification error', async () => {
      const password = 'SecurePass123!';
      const hash = 'invalid-hash';

      const bcrypt = require('bcrypt');
      bcrypt.compare = jest.fn().mockRejectedValue(new Error('Invalid hash'));

      const startTime = Date.now();
      const result = await authService.timingSafePasswordVerify(password, hash);
      const endTime = Date.now();

      expect(result).toBe(false);
      expect(endTime - startTime).toBeGreaterThanOrEqual(5); // Should have delay
      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('Service status', () => {
    it('should return correct service configuration', () => {
      const status = authService.getStatus();

      expect(status).toEqual({
        maxFailedAttempts: 5,
        lockoutDuration: 15 * 60 * 1000,
        jwtExpiry: '15m',
        refreshTokenExpiry: '7d',
        bcryptRounds: 12
      });
    });
  });
});

  describe('login()', () => {
    const validCredentials = {
      email: 'test@example.com',
      password: 'SecureP@ssw0rd!'
    };

    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      passwordHash: '$2b$12$test.hash.value',
      isActive: true,
      isAccountLocked: jest.fn().mockReturnValue(false),
      recordFailedLogin: jest.fn(),
      recordSuccessfulLogin: jest.fn(),
      lastLoginAt: new Date()
    };

    beforeEach(() => {
      // Reset rate limiting store
      authService.rateLimitStore = new Map();
      authService.refreshTokenStore = new Map();
      
      // Mock JWT
      const jwt = require('jsonwebtoken');
      jwt.sign = jest.fn()
        .mockReturnValueOnce('mock.access.token')
        .mockReturnValueOnce('mock.refresh.token');
    });

    it('should successfully login with valid credentials', async () => {
      User.findByEmail.mockResolvedValue(mockUser);
      
      const bcrypt = require('bcrypt');
      bcrypt.compare = jest.fn().mockResolvedValue(true);

      const result = await authService.login(validCredentials, '192.168.1.1');

      expect(result).toEqual({
        user: {
          id: 'user-123',
          email: 'test@example.com',
          isActive: true,
          lastLoginAt: mockUser.lastLoginAt
        },
        tokens: {
          accessToken: 'mock.access.token',
          refreshToken: 'mock.refresh.token',
          expiresIn: 900,
          tokenType: 'Bearer'
        }
      });

      expect(mockUser.recordSuccessfulLogin).toHaveBeenCalledWith('192.168.1.1');
      expect(logger.security.authSuccess).toHaveBeenCalledWith({
        action: 'user_login',
        userId: 'user-123',
        ipAddress: '192.168.1.1',
        email: '[REDACTED]'
      });
    });

    it('should reject login with invalid email', async () => {
      await expect(authService.login({
        email: 'invalid-email',
        password: 'SecureP@ssw0rd!'
      }, '192.168.1.1')).rejects.toThrow('Please enter a valid email address');
    });

    it('should reject login with missing password', async () => {
      await expect(authService.login({
        email: 'test@example.com',
        password: ''
      }, '192.168.1.1')).rejects.toThrow('Password is required');
    });

    it('should reject login with non-existent user', async () => {
      User.findByEmail.mockResolvedValue(null);
      
      const bcrypt = require('bcrypt');
      bcrypt.compare = jest.fn().mockResolvedValue(false);

      await expect(authService.login(validCredentials, '192.168.1.1'))
        .rejects.toThrow('Invalid email or password');

      expect(logger.security.authFailure).toHaveBeenCalledWith({
        action: 'user_login',
        error: 'Invalid email or password',
        ipAddress: '192.168.1.1',
        email: '[REDACTED]'
      });
    });

    it('should reject login with wrong password', async () => {
      User.findByEmail.mockResolvedValue(mockUser);
      
      const bcrypt = require('bcrypt');
      bcrypt.compare = jest.fn().mockResolvedValue(false);

      await expect(authService.login(validCredentials, '192.168.1.1'))
        .rejects.toThrow('Invalid email or password');

      expect(mockUser.recordFailedLogin).toHaveBeenCalledWith('192.168.1.1');
    });

    it('should reject login for locked account', async () => {
      const lockedUser = {
        ...mockUser,
        isAccountLocked: jest.fn().mockReturnValue(true)
      };
      
      User.findByEmail.mockResolvedValue(lockedUser);
      
      const bcrypt = require('bcrypt');
      bcrypt.compare = jest.fn().mockResolvedValue(true);

      await expect(authService.login(validCredentials, '192.168.1.1'))
        .rejects.toThrow('Account is temporarily locked due to too many failed login attempts');
    });

    it('should enforce IP-based rate limiting', async () => {
      // Simulate 10 failed attempts from same IP
      for (let i = 0; i < 10; i++) {
        await authService.recordFailedLoginAttempt('192.168.1.1', 'test@example.com');
      }

      await expect(authService.login(validCredentials, '192.168.1.1'))
        .rejects.toThrow('Too many login attempts from this IP address');
    });

    it('should enforce user-based rate limiting', async () => {
      // Simulate 5 failed attempts for same user
      for (let i = 0; i < 5; i++) {
        await authService.recordFailedLoginAttempt('192.168.1.1', 'test@example.com');
      }

      await expect(authService.login(validCredentials, '192.168.1.2'))
        .rejects.toThrow('Too many login attempts for this account');
    });

    it('should clear rate limit counters on successful login', async () => {
      // Add some failed attempts
      await authService.recordFailedLoginAttempt('192.168.1.1', 'test@example.com');
      
      User.findByEmail.mockResolvedValue(mockUser);
      
      const bcrypt = require('bcrypt');
      bcrypt.compare = jest.fn().mockResolvedValue(true);

      await authService.login(validCredentials, '192.168.1.1');

      // Verify counters are cleared
      const ipCount = await authService.getRateLimitCount('rate_limit:ip:192.168.1.1');
      const userCount = await authService.getRateLimitCount(`rate_limit:user:${authService.hashEmail('test@example.com')}`);
      
      expect(ipCount).toBe(0);
      expect(userCount).toBe(0);
    });

    it('should handle database errors gracefully', async () => {
      User.findByEmail.mockRejectedValue(new Error('Database connection failed'));

      await expect(authService.login(validCredentials, '192.168.1.1'))
        .rejects.toThrow('Login failed. Please try again.');

      expect(logger.security.authFailure).toHaveBeenCalled();
    });
  });

  describe('Rate limiting', () => {
    it('should track rate limit counts correctly', async () => {
      const key = 'test_key';
      
      expect(await authService.getRateLimitCount(key)).toBe(0);
      
      await authService.incrementRateLimitCount(key);
      expect(await authService.getRateLimitCount(key)).toBe(1);
      
      await authService.incrementRateLimitCount(key);
      expect(await authService.getRateLimitCount(key)).toBe(2);
      
      await authService.clearRateLimitCount(key);
      expect(await authService.getRateLimitCount(key)).toBe(0);
    });

    it('should expire rate limit entries after 15 minutes', async () => {
      const key = 'test_key';
      
      // Mock Date.now to simulate time passage
      const originalNow = Date.now;
      const mockNow = jest.fn();
      Date.now = mockNow;
      
      // Set initial time
      mockNow.mockReturnValue(1000000);
      await authService.incrementRateLimitCount(key);
      expect(await authService.getRateLimitCount(key)).toBe(1);
      
      // Simulate 16 minutes later
      mockNow.mockReturnValue(1000000 + 16 * 60 * 1000);
      expect(await authService.getRateLimitCount(key)).toBe(0);
      
      // Restore original Date.now
      Date.now = originalNow;
    });
  });

  describe('JWT token generation', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com'
    };

    it('should generate access and refresh tokens', async () => {
      const jwt = require('jsonwebtoken');
      jwt.sign = jest.fn()
        .mockReturnValueOnce('mock.access.token')
        .mockReturnValueOnce('mock.refresh.token');

      const tokens = await authService.generateTokens(mockUser);

      expect(tokens).toEqual({
        accessToken: 'mock.access.token',
        refreshToken: 'mock.refresh.token',
        expiresIn: 900,
        tokenType: 'Bearer'
      });

      expect(jwt.sign).toHaveBeenCalledTimes(2);
      
      // Check access token payload
      expect(jwt.sign).toHaveBeenNthCalledWith(1, 
        expect.objectContaining({
          userId: 'user-123',
          email: 'test@example.com',
          type: 'access'
        }),
        expect.any(String),
        expect.objectContaining({
          expiresIn: '15m'
        })
      );

      // Check refresh token payload
      expect(jwt.sign).toHaveBeenNthCalledWith(2,
        expect.objectContaining({
          userId: 'user-123',
          email: 'test@example.com',
          type: 'refresh',
          tokenId: expect.any(String)
        }),
        expect.any(String),
        expect.objectContaining({
          expiresIn: '7d'
        })
      );
    });

    it('should handle token generation errors', async () => {
      const jwt = require('jsonwebtoken');
      jwt.sign = jest.fn().mockImplementation(() => {
        throw new Error('JWT signing failed');
      });

      await expect(authService.generateTokens(mockUser))
        .rejects.toThrow('Token generation failed');

      expect(logger.error).toHaveBeenCalledWith('Token generation failed', {
        error: 'JWT signing failed',
        userId: 'user-123'
      });
    });
  });

  describe('Security utilities', () => {
    it('should hash emails consistently', () => {
      const email1 = 'test@example.com';
      const email2 = 'TEST@EXAMPLE.COM';
      const email3 = 'different@example.com';

      const hash1 = authService.hashEmail(email1);
      const hash2 = authService.hashEmail(email2);
      const hash3 = authService.hashEmail(email3);

      expect(hash1).toBe(hash2); // Same email, different case
      expect(hash1).not.toBe(hash3); // Different email
      expect(hash1).toMatch(/^[a-f0-9]{64}$/); // Valid SHA-256 hash
    });

    it('should identify authentication errors correctly', () => {
      const authError = new Error('Invalid email or password');
      const dbError = new Error('Connection timeout');
      const validationError = new Error('Email is required');

      expect(authService.isAuthenticationError(authError)).toBe(true);
      expect(authService.isAuthenticationError(dbError)).toBe(false);
      expect(authService.isAuthenticationError(validationError)).toBe(true);
    });
  });

  describe('Refresh token management', () => {
    it('should store refresh tokens correctly', async () => {
      const userId = 'user-123';
      const tokenId = 'token-456';
      const refreshToken = 'mock.refresh.token';

      await authService.storeRefreshToken(userId, tokenId, refreshToken);

      const key = `refresh_token:${userId}:${tokenId}`;
      expect(authService.refreshTokenStore.has(key)).toBe(true);
      
      const stored = authService.refreshTokenStore.get(key);
      expect(stored).toEqual({
        token: refreshToken,
        createdAt: expect.any(Number),
        userId
      });
    });
  });
});