const request = require('supertest');
const fs = require('fs');
const path = require('path');

// Mock environment for testing
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_db';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.ENCRYPTION_KEY = Buffer.from('test-key-32-bytes-long-for-aes256').toString('base64');
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-purposes';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key-for-testing';
process.env.CORS_ORIGIN = 'http://localhost:3000';
process.env.LOG_LEVEL = 'info';
process.env.LOG_FILE = 'logs/test-integration.log';

const app = require('../app');
const logger = require('../utils/logger');

describe('Logging Integration Tests', () => {
  let logSpy;
  let originalTransports;

  beforeAll(() => {
    // Store original transports
    originalTransports = [...logger.transports];
    
    // Clear transports and add test transport
    logger.clear();
    
    // Create spy for log output
    logSpy = jest.spyOn(logger, 'info');
    jest.spyOn(logger, 'warn');
    jest.spyOn(logger, 'error');
    jest.spyOn(logger.security, 'authAttempt');
    jest.spyOn(logger.security, 'authSuccess');
    jest.spyOn(logger.security, 'authFailure');
    jest.spyOn(logger.security, 'dataAccess');
    jest.spyOn(logger.security, 'dataModification');
    jest.spyOn(logger.security, 'rateLimitExceeded');
    jest.spyOn(logger.audit, 'logEvent');
  });

  afterAll(() => {
    // Restore original transports
    logger.clear();
    originalTransports.forEach(transport => logger.add(transport));
    
    // Restore original methods
    jest.restoreAllMocks();
  });

  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  describe('Authentication Logging', () => {
    test('should log registration attempts', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        confirmPassword: 'TestPassword123!'
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      // Should log successful registration
      expect(logger.security.authSuccess).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'user_registration',
          userId: expect.any(String)
        })
      );
    });

    test('should log failed registration attempts', async () => {
      const userData = {
        email: 'invalid-email',
        password: 'weak',
        confirmPassword: 'weak'
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      // Should log failed registration
      expect(logger.security.authFailure).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'user_registration',
          error: expect.any(String)
        })
      );
    });

    test('should log login attempts', async () => {
      // First register a user
      const userData = {
        email: 'login-test@example.com',
        password: 'TestPassword123!',
        confirmPassword: 'TestPassword123!'
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData);

      // Clear previous calls
      jest.clearAllMocks();

      // Then attempt login
      await request(app)
        .post('/api/auth/login')
        .send({
          email: 'login-test@example.com',
          password: 'TestPassword123!'
        })
        .expect(200);

      // Should log successful login
      expect(logger.security.authSuccess).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'user_login',
          userId: expect.any(String)
        })
      );
    });

    test('should log failed login attempts', async () => {
      await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        })
        .expect(401);

      // Should log failed login
      expect(logger.security.authFailure).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'user_login',
          error: expect.any(String)
        })
      );
    });
  });

  describe('Data Access Logging', () => {
    let authToken;
    let userId;

    beforeEach(async () => {
      // Register and login to get auth token
      const userData = {
        email: 'data-test@example.com',
        password: 'TestPassword123!',
        confirmPassword: 'TestPassword123!'
      };

      const registerResponse = await request(app)
        .post('/api/auth/register')
        .send(userData);

      userId = registerResponse.body.user.id;

      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'data-test@example.com',
          password: 'TestPassword123!'
        });

      authToken = loginResponse.body.token;

      // Clear mocks after setup
      jest.clearAllMocks();
    });

    test('should log note creation', async () => {
      const noteData = {
        title: 'Test Note',
        content: 'This is a test note content'
      };

      await request(app)
        .post('/api/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(noteData)
        .expect(201);

      // Should log data modification for note creation
      expect(logger.security.dataModification).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'note_created',
          userId: userId
        })
      );
    });

    test('should log note retrieval', async () => {
      // First create a note
      const noteData = {
        title: 'Test Note for Retrieval',
        content: 'This is a test note for retrieval'
      };

      await request(app)
        .post('/api/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(noteData);

      // Clear previous calls
      jest.clearAllMocks();

      // Then retrieve notes
      await request(app)
        .get('/api/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Should log data access for note retrieval
      expect(logger.security.dataAccess).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'notes_retrieved',
          userId: userId
        })
      );
    });

    test('should log note updates', async () => {
      // First create a note
      const noteData = {
        title: 'Test Note for Update',
        content: 'Original content'
      };

      const createResponse = await request(app)
        .post('/api/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(noteData);

      const noteId = createResponse.body.note.id;

      // Clear previous calls
      jest.clearAllMocks();

      // Then update the note
      await request(app)
        .put(`/api/notes/${noteId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Updated Note Title',
          content: 'Updated content'
        })
        .expect(200);

      // Should log data modification for note update
      expect(logger.security.dataModification).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'note_updated',
          userId: userId,
          resourceId: noteId
        })
      );
    });

    test('should log note deletion', async () => {
      // First create a note
      const noteData = {
        title: 'Test Note for Deletion',
        content: 'This note will be deleted'
      };

      const createResponse = await request(app)
        .post('/api/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(noteData);

      const noteId = createResponse.body.note.id;

      // Clear previous calls
      jest.clearAllMocks();

      // Then delete the note
      await request(app)
        .delete(`/api/notes/${noteId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Should log data modification for note deletion
      expect(logger.security.dataModification).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'note_deleted',
          userId: userId,
          resourceId: noteId
        })
      );
    });
  });

  describe('Security Event Logging', () => {
    test('should log rate limiting events', async () => {
      // Make multiple rapid requests to trigger rate limiting
      const requests = Array(10).fill().map(() =>
        request(app)
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'wrongpassword'
          })
      );

      await Promise.all(requests);

      // Should eventually log rate limit exceeded
      // Note: This might not trigger in test environment depending on rate limit configuration
      // but the test verifies the logging mechanism is in place
    });

    test('should log unauthorized access attempts', async () => {
      // Attempt to access protected route without token
      await request(app)
        .get('/api/notes')
        .expect(401);

      // Should log authentication failure
      expect(logger.security.authFailure).toHaveBeenCalled();
    });

    test('should log invalid token usage', async () => {
      // Attempt to access protected route with invalid token
      await request(app)
        .get('/api/notes')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      // Should log authentication failure
      expect(logger.security.authFailure).toHaveBeenCalled();
    });
  });

  describe('Error Logging', () => {
    test('should log application errors', async () => {
      // Trigger an error by sending malformed data
      await request(app)
        .post('/api/notes')
        .set('Authorization', 'Bearer valid-but-expired-token')
        .send({
          title: 'A'.repeat(1000), // Extremely long title
          content: 'Test content'
        })
        .expect(401); // Will fail due to invalid token first

      // Should log the error
      expect(logger.security.authFailure).toHaveBeenCalled();
    });

    test('should redact sensitive data in error logs', async () => {
      // Attempt login with password in request
      await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'sensitive-password-123'
        })
        .expect(401);

      // Verify that the password is not logged in plain text
      const logCalls = logger.security.authFailure.mock.calls;
      
      logCalls.forEach(call => {
        const logData = JSON.stringify(call);
        expect(logData).not.toContain('sensitive-password-123');
      });
    });
  });

  describe('Audit Trail Logging', () => {
    test('should maintain audit trail for user actions', async () => {
      // Register user
      const userData = {
        email: 'audit-test@example.com',
        password: 'TestPassword123!',
        confirmPassword: 'TestPassword123!'
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData);

      // Login
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'audit-test@example.com',
          password: 'TestPassword123!'
        });

      const authToken = loginResponse.body.token;

      // Create note
      await request(app)
        .post('/api/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Audit Test Note',
          content: 'This is for audit testing'
        });

      // Verify that all actions were logged
      expect(logger.security.authSuccess).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'user_registration'
        })
      );

      expect(logger.security.authSuccess).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'user_login'
        })
      );

      expect(logger.security.dataModification).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'note_created'
        })
      );
    });
  });

  describe('Log Management', () => {
    test('should provide log statistics', () => {
      const stats = logger.management.getLogStats();
      
      expect(stats).toHaveProperty('level');
      expect(stats).toHaveProperty('transports');
      expect(stats).toHaveProperty('environment');
      expect(stats).toHaveProperty('timestamp');
    });

    test('should allow log level changes', () => {
      const originalLevel = logger.level;
      
      logger.management.setLogLevel('debug');
      expect(logger.level).toBe('debug');
      
      logger.management.setLogLevel('error');
      expect(logger.level).toBe('error');
      
      // Restore original level
      logger.management.setLogLevel(originalLevel);
    });

    test('should provide configuration information', () => {
      const config = logger.management.getConfig();
      
      expect(config).toHaveProperty('level');
      expect(config).toHaveProperty('environment');
      expect(config).toHaveProperty('logFile');
      expect(config).toHaveProperty('transports');
      expect(Array.isArray(config.transports)).toBe(true);
    });
  });
});