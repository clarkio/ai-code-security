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

describe('AuthService - JWT Token Validation and Session Management', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock logger methods
    logger.security = {
      authSuccess: jest.fn(),
      authFailure: jest.fn()
    };
    logger.error = jest.fn();
    logger.info = jest.fn();

    // Reset stores
    authService.refreshTokenStore = new Map();
    authService.tokenBlacklist = new Set();
  });

  describe('validateAccessToken()', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      isActive: true,
      lastLoginAt: new Date()
    };

    it('should validate a valid access token', async () => {
      const jwt = require('jsonwebtoken');
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access'
      };

      const token = jwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      User.findById.mockResolvedValue(mockUser);

      const result = await authService.validateAccessToken(token);

      expect(result).toEqual({
        userId: 'user-123',
        email: 'test@example.com',
        user: mockUser
      });
    });

    it('should validate token with Bearer prefix', async () => {
      const jwt = require('jsonwebtoken');
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access'
      };

      const token = jwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      User.findById.mockResolvedValue(mockUser);

      const result = await authService.validateAccessToken(`Bearer ${token}`);

      expect(result.userId).toBe('user-123');
    });

    it('should reject missing token', async () => {
      await expect(authService.validateAccessToken(''))
        .rejects.toThrow('Token is required');

      await expect(authService.validateAccessToken(null))
        .rejects.toThrow('Token is required');
    });

    it('should reject invalid token', async () => {
      await expect(authService.validateAccessToken('invalid.token.here'))
        .rejects.toThrow('Invalid token');

      expect(logger.security.authFailure).toHaveBeenCalledWith({
        action: 'token_validation',
        error: 'invalid token',
        token: '[REDACTED]'
      });
    });

    it('should reject expired token', async () => {
      const jwt = require('jsonwebtoken');
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access'
      };

      const expiredToken = jwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        expiresIn: '-1h', // Expired 1 hour ago
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      await expect(authService.validateAccessToken(expiredToken))
        .rejects.toThrow('Token has expired');
    });

    it('should reject blacklisted token', async () => {
      const jwt = require('jsonwebtoken');
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access'
      };

      const token = jwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      // Blacklist the token
      await authService.blacklistToken(token);

      await expect(authService.validateAccessToken(token))
        .rejects.toThrow('Token has been revoked');
    });

    it('should reject wrong token type', async () => {
      const jwt = require('jsonwebtoken');
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'refresh' // Wrong type
      };

      const token = jwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      await expect(authService.validateAccessToken(token))
        .rejects.toThrow('Invalid token type');
    });

    it('should reject token for inactive user', async () => {
      const jwt = require('jsonwebtoken');
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access'
      };

      const token = jwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      User.findById.mockResolvedValue({ ...mockUser, isActive: false });

      await expect(authService.validateAccessToken(token))
        .rejects.toThrow('User not found or inactive');
    });

    it('should reject token for non-existent user', async () => {
      const jwt = require('jsonwebtoken');
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access'
      };

      const token = jwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      User.findById.mockResolvedValue(null);

      await expect(authService.validateAccessToken(token))
        .rejects.toThrow('User not found or inactive');
    });
  });

  describe('refreshAccessToken()', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      isActive: true
    };

    it('should refresh access token with valid refresh token', async () => {
      const jwt = require('jsonwebtoken');
      const tokenId = 'token-456';
      const refreshPayload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'refresh',
        tokenId
      };

      const refreshToken = jwt.sign(refreshPayload, 'test-jwt-refresh-secret-key-for-testing', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      // Store refresh token
      await authService.storeRefreshToken('user-123', tokenId, refreshToken);

      User.findById.mockResolvedValue(mockUser);

      // Mock JWT sign for new tokens
      const originalSign = jwt.sign;
      jwt.sign = jest.fn()
        .mockReturnValueOnce('new.access.token')
        .mockReturnValueOnce('new.refresh.token');

      const result = await authService.refreshAccessToken(refreshToken);

      expect(result).toEqual({
        accessToken: 'new.access.token',
        refreshToken: 'new.refresh.token',
        expiresIn: 900,
        tokenType: 'Bearer'
      });

      expect(logger.security.authSuccess).toHaveBeenCalledWith({
        action: 'token_refresh',
        userId: 'user-123',
        email: '[REDACTED]'
      });

      // Verify old refresh token was removed
      const oldToken = await authService.getStoredRefreshToken('user-123', tokenId);
      expect(oldToken).toBeNull();

      // Restore original JWT sign
      jwt.sign = originalSign;
    });

    it('should reject missing refresh token', async () => {
      await expect(authService.refreshAccessToken(''))
        .rejects.toThrow('Refresh token is required');

      await expect(authService.refreshAccessToken(null))
        .rejects.toThrow('Refresh token is required');
    });

    it('should reject invalid refresh token', async () => {
      await expect(authService.refreshAccessToken('invalid.token.here'))
        .rejects.toThrow('Invalid refresh token');

      expect(logger.security.authFailure).toHaveBeenCalledWith({
        action: 'token_refresh',
        error: 'invalid token',
        refreshToken: '[REDACTED]'
      });
    });

    it('should reject expired refresh token', async () => {
      const refreshPayload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'refresh',
        tokenId: 'token-456'
      };

      // Create a real JWT token that's expired
      const realJwt = require('jsonwebtoken');
      const expiredRefreshToken = realJwt.sign(refreshPayload, 'test-jwt-refresh-secret-key-for-testing', {
        expiresIn: '-1d', // Expired 1 day ago
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      await expect(authService.refreshAccessToken(expiredRefreshToken))
        .rejects.toThrow('Refresh token has expired');
    });

    it('should reject refresh token not in store', async () => {
      const tokenId = 'token-456';
      const refreshPayload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'refresh',
        tokenId
      };

      // Create a real JWT token
      const realJwt = require('jsonwebtoken');
      const refreshToken = realJwt.sign(refreshPayload, 'test-jwt-refresh-secret-key-for-testing', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      // Don't store the token

      await expect(authService.refreshAccessToken(refreshToken))
        .rejects.toThrow('Refresh token not found or invalid');
    });

    it('should reject wrong token type', async () => {
      const refreshPayload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access', // Wrong type
        tokenId: 'token-456'
      };

      // Create a real JWT token
      const realJwt = require('jsonwebtoken');
      const refreshToken = realJwt.sign(refreshPayload, 'test-jwt-refresh-secret-key-for-testing', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      await expect(authService.refreshAccessToken(refreshToken))
        .rejects.toThrow('Invalid token type');
    });

    it('should reject refresh token for inactive user', async () => {
      const tokenId = 'token-456';
      const refreshPayload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'refresh',
        tokenId
      };

      // Create a real JWT token
      const realJwt = require('jsonwebtoken');
      const refreshToken = realJwt.sign(refreshPayload, 'test-jwt-refresh-secret-key-for-testing', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      await authService.storeRefreshToken('user-123', tokenId, refreshToken);
      User.findById.mockResolvedValue({ ...mockUser, isActive: false });

      await expect(authService.refreshAccessToken(refreshToken))
        .rejects.toThrow('User not found or inactive');
    });
  });

  describe('logout()', () => {
    it('should logout successfully with both tokens', async () => {
      const jwt = require('jsonwebtoken');
      const accessToken = 'Bearer access.token.here';
      const refreshToken = 'refresh.token.here';

      // Mock JWT decode
      jwt.decode = jest.fn()
        .mockReturnValueOnce({ userId: 'user-123' })
        .mockReturnValueOnce({ tokenId: 'token-456' });

      const result = await authService.logout(accessToken, refreshToken);

      expect(result).toEqual({
        success: true,
        message: 'Logged out successfully'
      });

      expect(logger.security.authSuccess).toHaveBeenCalledWith({
        action: 'user_logout',
        userId: 'user-123',
        message: 'User logged out successfully'
      });

      // Verify token was blacklisted
      expect(await authService.isTokenBlacklisted('access.token.here')).toBe(true);
    });

    it('should logout successfully with only access token', async () => {
      const jwt = require('jsonwebtoken');
      const accessToken = 'Bearer access.token.here';

      jwt.decode = jest.fn().mockReturnValueOnce({ userId: 'user-123' });

      const result = await authService.logout(accessToken, null);

      expect(result.success).toBe(true);
      expect(await authService.isTokenBlacklisted('access.token.here')).toBe(true);
    });

    it('should logout successfully even with invalid tokens', async () => {
      const jwt = require('jsonwebtoken');
      jwt.decode = jest.fn().mockImplementation(() => {
        throw new Error('Invalid token');
      });

      const result = await authService.logout('invalid.token', 'invalid.refresh');

      expect(result.success).toBe(true);
    });

    it('should logout successfully with no tokens', async () => {
      const result = await authService.logout(null, null);

      expect(result.success).toBe(true);
    });
  });

  describe('validateSession()', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      isActive: true,
      lastLoginAt: new Date()
    };

    it('should validate valid session', async () => {
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access'
      };

      // Create a real JWT token
      const realJwt = require('jsonwebtoken');
      const token = realJwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      User.findById.mockResolvedValue(mockUser);

      const result = await authService.validateSession(token);

      expect(result).toEqual({
        valid: true,
        user: {
          id: 'user-123',
          email: 'test@example.com',
          isActive: true,
          lastLoginAt: mockUser.lastLoginAt
        }
      });
    });

    it('should return invalid for bad token', async () => {
      const result = await authService.validateSession('invalid.token');

      expect(result).toEqual({
        valid: false,
        error: 'Invalid token'
      });
    });
  });

  describe('Token blacklisting', () => {
    it('should blacklist and check tokens correctly', async () => {
      const token = 'test.token.here';

      expect(await authService.isTokenBlacklisted(token)).toBe(false);

      await authService.blacklistToken(token);
      expect(await authService.isTokenBlacklisted(token)).toBe(true);

      // Should handle Bearer prefix
      await authService.blacklistToken(`Bearer ${token}`);
      expect(await authService.isTokenBlacklisted(token)).toBe(true);
    });
  });

  describe('Refresh token management', () => {
    it('should store and retrieve refresh tokens', async () => {
      const userId = 'user-123';
      const tokenId = 'token-456';
      const refreshToken = 'refresh.token.here';

      await authService.storeRefreshToken(userId, tokenId, refreshToken);

      const stored = await authService.getStoredRefreshToken(userId, tokenId);
      expect(stored).toEqual({
        token: refreshToken,
        createdAt: expect.any(Number),
        userId
      });

      await authService.removeStoredRefreshToken(userId, tokenId);
      const removed = await authService.getStoredRefreshToken(userId, tokenId);
      expect(removed).toBeNull();
    });

    it('should clean up expired tokens', async () => {
      const userId = 'user-123';
      const tokenId1 = 'token-1';
      const tokenId2 = 'token-2';

      // Mock Date.now for consistent timing
      const originalNow = Date.now;
      const mockNow = jest.fn();
      Date.now = mockNow;

      // Set initial time
      mockNow.mockReturnValue(1000000);
      await authService.storeRefreshToken(userId, tokenId1, 'token1');

      // Set time 8 days later (expired)
      mockNow.mockReturnValue(1000000 + 8 * 24 * 60 * 60 * 1000);
      await authService.storeRefreshToken(userId, tokenId2, 'token2');

      // Clean up expired tokens
      const result = await authService.cleanupExpiredTokens();

      expect(result.cleaned).toBe(1);
      expect(await authService.getStoredRefreshToken(userId, tokenId1)).toBeNull();
      expect(await authService.getStoredRefreshToken(userId, tokenId2)).toBeTruthy();

      // Restore original Date.now
      Date.now = originalNow;
    });
  });

  describe('Auth middleware', () => {
    it('should create working auth middleware', async () => {
      const middleware = authService.createAuthMiddleware();

      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        type: 'access'
      };

      // Create a real JWT token
      const realJwt = require('jsonwebtoken');
      const token = realJwt.sign(payload, 'test-jwt-secret-key-for-testing-purposes', {
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      User.findById.mockResolvedValue(mockUser);

      const req = {
        headers: {
          authorization: `Bearer ${token}`
        }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      const next = jest.fn();

      await middleware(req, res, next);

      expect(req.user).toEqual(mockUser);
      expect(req.userId).toBe('user-123');
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should reject request without authorization header', async () => {
      const middleware = authService.createAuthMiddleware();

      const req = { headers: {} };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      const next = jest.fn();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Authorization header required',
        code: 'MISSING_TOKEN'
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject request with invalid token', async () => {
      const middleware = authService.createAuthMiddleware();

      const req = {
        headers: {
          authorization: 'Bearer invalid.token'
        }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      const next = jest.fn();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('Service status', () => {
    it('should return correct service status with token stores', () => {
      authService.rateLimitStore = new Map([['key1', 'value1']]);
      authService.refreshTokenStore = new Map([['key1', 'value1'], ['key2', 'value2']]);
      authService.tokenBlacklist = new Set(['token1', 'token2', 'token3']);

      const status = authService.getStatus();

      expect(status).toEqual({
        maxFailedAttempts: 5,
        lockoutDuration: 15 * 60 * 1000,
        jwtExpiry: '15m',
        refreshTokenExpiry: '7d',
        bcryptRounds: 12,
        rateLimitStore: 1,
        refreshTokenStore: 2,
        tokenBlacklist: 3
      });
    });
  });
});