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

describe('AuthService - Login Security', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock logger methods
    logger.security = {
      authSuccess: jest.fn(),
      authFailure: jest.fn()
    };
    logger.error = jest.fn();
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