const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = require('../app');
const authService = require('../services/authService');
const User = require('../models/User');

// Load test environment
require('./setup');

// Mock dependencies
jest.mock('../utils/logger', () => ({
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
  security: {
    authSuccess: jest.fn(),
    authFailure: jest.fn()
  }
}));

jest.mock('../models/User');

describe('Authentication Security Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset rate limiting store
    authService.rateLimitStore = new Map();
    authService.refreshTokenStore = new Map();
    authService.tokenBlacklist = new Set();
  });

  describe('Password Complexity Enforcement', () => {
    test('should reject passwords shorter than 12 characters', async () => {
      const shortPasswords = [
        'Short1!',     // 7 chars
        'Tiny1!',      // 6 chars  
        'Small1!'      // 7 chars
      ];

      for (const password of shortPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).toThrow(/Password requirements not met/);
      }
    });

    test('should reject passwords without lowercase letters', async () => {
      const weakPasswords = [
        'NOLOWERCASE123!',
        'UPPERCASE123456!',
        '123456789012!'
      ];

      for (const password of weakPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).toThrow('Password must contain at least one lowercase letter');
      }
    });

    test('should reject passwords without uppercase letters', async () => {
      const weakPasswords = [
        'nouppercase123!',
        'lowercase123456!',
        'alllowercase123!'
      ];

      for (const password of weakPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).toThrow('Password must contain at least one uppercase letter');
      }
    });

    test('should reject passwords without numbers', async () => {
      const weakPasswords = [
        'NoNumbersHere!',
        'OnlyLettersAndSymbols!',
        'PasswordWithoutDigits!'
      ];

      for (const password of weakPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).toThrow('Password must contain at least one number');
      }
    });

    test('should reject passwords without special characters', async () => {
      const weakPasswords = [
        'NoSpecialChars123',
        'OnlyAlphanumeric123',
        'MissingSymbols123'
      ];

      for (const password of weakPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).toThrow('Password must contain at least one special character');
      }
    });

    test('should reject common weak passwords', async () => {
      const commonPasswords = [
        'Password123!',
        'Welcome123!',
        'Letmein123!',
        'Admin123456!',
        'Qwerty123456!'
      ];

      for (const password of commonPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).toThrow('Password contains common patterns');
      }
    });

    test('should reject passwords with sequential characters', async () => {
      const sequentialPasswords = [
        'Abc123456789!',
        'Password123!',
        'Qwerty123456!',
        'Asdf123456789!'
      ];

      for (const password of sequentialPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).toThrow('sequential characters');
      }
    });

    test('should reject passwords with repeated characters', async () => {
      const repeatedPasswords = [
        'MyPasssssword1!',
        'Testtttword123!',
        'Hellllloworld1!'
      ];

      for (const password of repeatedPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).toThrow(/excessive repeated characters/);
      }
    });

    test('should accept strong passwords', async () => {
      const strongPasswords = [
        'MyStr0ng!P@ssw0rd',
        'C0mpl3x!S3cur3P@ss',
        'Un1qu3&S@f3P@ssw0rd',
        'V3ry!S3cur3P@ssw0rd2024'
      ];

      for (const password of strongPasswords) {
        expect(() => {
          authService.validatePasswordComplexity(password);
        }).not.toThrow();
      }
    });
  });

  describe('Brute Force Attack Prevention', () => {
    test('should implement rate limiting per IP address', async () => {
      const ipAddress = '192.168.1.100';
      
      // Simulate multiple failed login attempts from same IP
      for (let i = 0; i < 10; i++) {
        await authService.recordFailedLoginAttempt(ipAddress, 'test@example.com');
      }

      // Next attempt should be rate limited
      try {
        await authService.checkRateLimit(ipAddress, 'test@example.com');
        fail('Expected rate limiting to be triggered');
      } catch (error) {
        expect(error.message).toContain('Too many login attempts from this IP address');
      }
    });

    test('should implement rate limiting per user account', async () => {
      const email = 'test@example.com';
      
      // Simulate multiple failed login attempts for same user
      for (let i = 0; i < 5; i++) {
        await authService.recordFailedLoginAttempt('192.168.1.1', email);
      }

      // Next attempt should be rate limited
      try {
        await authService.checkRateLimit('192.168.1.2', email);
        fail('Expected user-based rate limiting to be triggered');
      } catch (error) {
        expect(error.message).toContain('Too many login attempts for this account');
      }
    });

    test('should clear rate limit counters on successful login', async () => {
      const ipAddress = '192.168.1.100';
      const email = 'test@example.com';
      
      // Record some failed attempts
      await authService.recordFailedLoginAttempt(ipAddress, email);
      await authService.recordFailedLoginAttempt(ipAddress, email);
      
      // Verify counters exist
      expect(await authService.getRateLimitCount(`rate_limit:ip:${ipAddress}`)).toBe(2);
      
      // Clear counters
      await authService.clearRateLimitCounters(ipAddress, email);
      
      // Verify counters are cleared
      expect(await authService.getRateLimitCount(`rate_limit:ip:${ipAddress}`)).toBe(0);
    });

    test('should implement account lockout after failed attempts', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        passwordHash: await bcrypt.hash('correctpassword', 12),
        failedLoginAttempts: 5,
        accountLockedUntil: new Date(Date.now() + 15 * 60 * 1000),
        isAccountLocked: jest.fn().mockReturnValue(true),
        recordFailedLogin: jest.fn(),
        recordSuccessfulLogin: jest.fn()
      };

      User.findByEmail.mockResolvedValue(mockUser);

      try {
        await authService.login({
          email: 'test@example.com',
          password: 'correctpassword'
        }, '192.168.1.1');
        fail('Expected account lockout to prevent login');
      } catch (error) {
        expect(error.message).toContain('Account is temporarily locked');
      }
    });

    test('should use timing-safe password verification', async () => {
      const password = 'testpassword';
      const hash = await bcrypt.hash(password, 12);
      
      // Measure timing for valid password
      const start1 = Date.now();
      const result1 = await authService.timingSafePasswordVerify(password, hash);
      const time1 = Date.now() - start1;
      
      // Measure timing for invalid password
      const start2 = Date.now();
      const result2 = await authService.timingSafePasswordVerify('wrongpassword', hash);
      const time2 = Date.now() - start2;
      
      expect(result1).toBe(true);
      expect(result2).toBe(false);
      
      // Both operations should take similar time (within reasonable variance)
      const timeDifference = Math.abs(time1 - time2);
      expect(timeDifference).toBeLessThan(50); // Allow 50ms variance
    });

    test('should prevent user enumeration through timing attacks', async () => {
      // Mock user not found scenario
      User.findByEmail.mockResolvedValue(null);
      
      const start1 = Date.now();
      try {
        await authService.login({
          email: 'nonexistent@example.com',
          password: 'anypassword'
        }, '192.168.1.1');
      } catch (error) {
        // Expected to fail
      }
      const time1 = Date.now() - start1;
      
      // Mock user found scenario with wrong password
      const mockUser = {
        id: 'user-123',
        email: 'existing@example.com',
        passwordHash: await bcrypt.hash('correctpassword', 12),
        isAccountLocked: jest.fn().mockReturnValue(false),
        recordFailedLogin: jest.fn()
      };
      
      User.findByEmail.mockResolvedValue(mockUser);
      
      const start2 = Date.now();
      try {
        await authService.login({
          email: 'existing@example.com',
          password: 'wrongpassword'
        }, '192.168.1.1');
      } catch (error) {
        // Expected to fail
      }
      const time2 = Date.now() - start2;
      
      // Both scenarios should take similar time
      const timeDifference = Math.abs(time1 - time2);
      expect(timeDifference).toBeLessThan(100); // Allow 100ms variance
    });
  });

  describe('Session Hijacking Prevention', () => {
    test('should generate unique JWT tokens with proper claims', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      const tokens = await authService.generateTokens(mockUser);
      
      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
      expect(tokens.tokenType).toBe('Bearer');
      expect(tokens.expiresIn).toBe(15 * 60); // 15 minutes
      
      // Decode and verify token structure
      const decoded = jwt.decode(tokens.accessToken);
      expect(decoded.userId).toBe(mockUser.id);
      expect(decoded.email).toBe(mockUser.email);
      expect(decoded.type).toBe('access');
      expect(decoded.iss).toBeDefined();
      expect(decoded.aud).toBeDefined();
      expect(decoded.exp).toBeDefined();
    });

    test('should implement refresh token rotation', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      // Generate initial tokens
      const initialTokens = await authService.generateTokens(mockUser);
      const initialRefreshDecoded = jwt.decode(initialTokens.refreshToken);
      
      // Mock user lookup for refresh
      User.findById.mockResolvedValue(mockUser);
      
      // Wait a moment to ensure different timestamps
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Refresh tokens
      const newTokens = await authService.refreshAccessToken(initialTokens.refreshToken);
      const newRefreshDecoded = jwt.decode(newTokens.refreshToken);
      
      // Verify new tokens have different token IDs (which ensures they're different)
      expect(newRefreshDecoded.tokenId).not.toBe(initialRefreshDecoded.tokenId);
      
      // Verify old refresh token is invalidated
      try {
        await authService.refreshAccessToken(initialTokens.refreshToken);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain('Refresh token not found or invalid');
      }
    });

    test('should invalidate tokens on logout', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      const tokens = await authService.generateTokens(mockUser);
      
      // Logout should blacklist tokens
      await authService.logout(tokens.accessToken, tokens.refreshToken);
      
      // Verify access token is blacklisted
      const isBlacklisted = await authService.isTokenBlacklisted(tokens.accessToken);
      expect(isBlacklisted).toBe(true);
      
      // Verify refresh token is removed from store
      const refreshDecoded = jwt.decode(tokens.refreshToken);
      const storedToken = await authService.getStoredRefreshToken(mockUser.id, refreshDecoded.tokenId);
      expect(storedToken).toBeNull();
    });

    test('should validate token issuer and audience', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      User.findById.mockResolvedValue(mockUser);

      // Create token with wrong issuer
      const maliciousToken = jwt.sign({
        userId: mockUser.id,
        email: mockUser.email,
        type: 'access'
      }, process.env.JWT_SECRET, {
        expiresIn: '15m',
        issuer: 'malicious-app',
        audience: 'secure-notes-users'
      });

      try {
        await authService.validateAccessToken(maliciousToken);
        fail('Expected token with wrong issuer to be rejected');
      } catch (error) {
        expect(error.message).toContain('Invalid token');
      }
    });

    test('should prevent session fixation attacks', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      // Generate multiple tokens for same user
      const tokens1 = await authService.generateTokens(mockUser);
      const tokens2 = await authService.generateTokens(mockUser);
      
      // Each refresh token should have unique ID (which ensures uniqueness)
      const decoded1 = jwt.decode(tokens1.refreshToken);
      const decoded2 = jwt.decode(tokens2.refreshToken);
      expect(decoded1.tokenId).not.toBe(decoded2.tokenId);
      
      // This proves tokens are unique even if generated at same time
      expect(decoded1.tokenId).toBeDefined();
      expect(decoded2.tokenId).toBeDefined();
      expect(typeof decoded1.tokenId).toBe('string');
      expect(typeof decoded2.tokenId).toBe('string');
    });
  });

  describe('JWT Token Manipulation Security', () => {
    test('should reject tokens with modified payload', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      const tokens = await authService.generateTokens(mockUser);
      
      // Decode token and modify payload
      const decoded = jwt.decode(tokens.accessToken);
      const modifiedPayload = {
        ...decoded,
        userId: 'admin-456', // Try to escalate privileges
        email: 'admin@example.com'
      };
      
      // Create new token with modified payload but wrong signature
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify(modifiedPayload)).toString('base64url');
      const maliciousToken = `${header}.${payload}.fake-signature`;
      
      try {
        await authService.validateAccessToken(maliciousToken);
        fail('Expected modified token to be rejected');
      } catch (error) {
        expect(error.message).toContain('Invalid token');
      }
    });

    test('should reject tokens with wrong signature', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      // Create token with wrong secret
      const maliciousToken = jwt.sign({
        userId: mockUser.id,
        email: mockUser.email,
        type: 'access'
      }, 'wrong-secret', {
        expiresIn: '15m',
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      try {
        await authService.validateAccessToken(maliciousToken);
        fail('Expected token with wrong signature to be rejected');
      } catch (error) {
        expect(error.message).toContain('Invalid token');
      }
    });

    test('should reject expired tokens', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      // Create expired token
      const expiredToken = jwt.sign({
        userId: mockUser.id,
        email: mockUser.email,
        type: 'access'
      }, process.env.JWT_SECRET, {
        expiresIn: '-1s', // Already expired
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      try {
        await authService.validateAccessToken(expiredToken);
        fail('Expected expired token to be rejected');
      } catch (error) {
        expect(error.message).toContain('Token has expired');
      }
    });

    test('should reject tokens with wrong type', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: true
      };

      User.findById.mockResolvedValue(mockUser);

      // Create token with wrong type
      const wrongTypeToken = jwt.sign({
        userId: mockUser.id,
        email: mockUser.email,
        type: 'refresh' // Wrong type for access token validation
      }, process.env.JWT_SECRET, {
        expiresIn: '15m',
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      try {
        await authService.validateAccessToken(wrongTypeToken);
        fail('Expected token with wrong type to be rejected');
      } catch (error) {
        expect(error.message).toContain('Invalid token type');
      }
    });

    test('should reject tokens for inactive users', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isActive: false // User is inactive
      };

      User.findById.mockResolvedValue(mockUser);

      const validToken = jwt.sign({
        userId: mockUser.id,
        email: mockUser.email,
        type: 'access'
      }, process.env.JWT_SECRET, {
        expiresIn: '15m',
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      try {
        await authService.validateAccessToken(validToken);
        fail('Expected token for inactive user to be rejected');
      } catch (error) {
        expect(error.message).toContain('User not found or inactive');
      }
    });

    test('should reject tokens for non-existent users', async () => {
      User.findById.mockResolvedValue(null);

      const validToken = jwt.sign({
        userId: 'non-existent-user',
        email: 'test@example.com',
        type: 'access'
      }, process.env.JWT_SECRET, {
        expiresIn: '15m',
        issuer: 'secure-notes-app',
        audience: 'secure-notes-users'
      });

      try {
        await authService.validateAccessToken(validToken);
        fail('Expected token for non-existent user to be rejected');
      } catch (error) {
        expect(error.message).toContain('User not found or inactive');
      }
    });

    test('should validate token format and structure', async () => {
      const invalidTokens = [
        '', // Empty token
        'invalid-token', // Not JWT format
        'header.payload', // Missing signature
        'header.payload.signature.extra', // Too many parts
        'not.base64.encoded', // Invalid base64
      ];

      for (const invalidToken of invalidTokens) {
        try {
          await authService.validateAccessToken(invalidToken);
          expect(true).toBe(false); // Should not reach here
        } catch (error) {
          // Empty token should give "Token is required" error
          if (invalidToken === '') {
            expect(error.message).toContain('Token is required');
          } else {
            expect(error.message).toContain('Invalid token');
          }
        }
      }
    });
  });
});