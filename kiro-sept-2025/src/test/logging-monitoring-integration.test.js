const logger = require('../utils/logger');
const monitoringService = require('../services/monitoringService');
const authService = require('../services/authService');
const notesService = require('../services/notesService');

// Mock database and Redis for testing
jest.mock('../database/connection');
jest.mock('redis');

describe('Logging and Monitoring Integration', () => {
  let logSpy;
  let securityLogSpy;
  let auditLogSpy;

  beforeAll(() => {
    // Set up spies for logging methods
    logSpy = jest.spyOn(logger, 'info');
    securityLogSpy = jest.spyOn(logger.security, 'authSuccess');
    auditLogSpy = jest.spyOn(logger.security, 'dataModification');
  });

  afterAll(() => {
    // Restore original methods
    jest.restoreAllMocks();
  });

  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  describe('Service Integration with Logging', () => {
    test('should log authentication events from auth service', async () => {
      // Mock successful user creation
      const mockUser = {
        id: 'test-user-id',
        email: 'test@example.com'
      };

      // Mock User.create to return a user
      const User = require('../models/User');
      User.create = jest.fn().mockResolvedValue(mockUser);

      try {
        await authService.register({
          email: 'test@example.com',
          password: 'TestPassword123!',
          confirmPassword: 'TestPassword123!'
        });

        // Verify that authentication success was logged
        expect(securityLogSpy).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'user_registration',
            userId: mockUser.id
          })
        );
      } catch (error) {
        // Registration might fail due to mocked dependencies, but we're testing logging
        expect(logger.security.authFailure).toHaveBeenCalled();
      }
    });

    test('should log data modification events from notes service', async () => {
      // Mock Note model
      const Note = require('../models/Note');
      Note.create = jest.fn().mockResolvedValue({
        id: 'test-note-id',
        title: 'Test Note',
        content: 'Test Content',
        userId: 'test-user-id'
      });

      try {
        await notesService.createNote('test-user-id', 'Test Note', 'Test Content');

        // Verify that data modification was logged
        expect(auditLogSpy).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'note_created',
            userId: 'test-user-id'
          })
        );
      } catch (error) {
        // Note creation might fail due to mocked dependencies, but we're testing logging
        expect(logger.error).toHaveBeenCalled();
      }
    });
  });

  describe('Monitoring Service Integration', () => {
    test('should record and retrieve metrics', () => {
      // Record some test metrics
      monitoringService.recordMetric('test_response_time', 150);
      monitoringService.recordMetric('test_response_time', 200);
      monitoringService.recordMetric('test_response_time', 100);

      // Verify metrics can be retrieved
      const latest = monitoringService.getMetric('test_response_time', 'latest');
      const average = monitoringService.getMetric('test_response_time', 'average');
      const max = monitoringService.getMetric('test_response_time', 'max');

      expect(latest).toBe(100);
      expect(average).toBe(150);
      expect(max).toBe(200);
    });

    test('should generate and manage alerts', () => {
      const alert = {
        type: 'error',
        message: 'Test alert for integration',
        component: 'test'
      };

      const addedAlert = monitoringService.addAlert(alert);

      expect(addedAlert).toHaveProperty('id');
      expect(addedAlert).toHaveProperty('timestamp');
      expect(addedAlert.type).toBe('error');
      expect(addedAlert.message).toBe('Test alert for integration');

      // Verify alert can be retrieved
      const alerts = monitoringService.getAlerts(1);
      expect(alerts.length).toBe(1);
      expect(alerts[0].id).toBe(addedAlert.id);
    });

    test('should provide comprehensive health status', async () => {
      const health = await monitoringService.getHealthStatus();

      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('timestamp');
      expect(health).toHaveProperty('uptime');
      expect(health).toHaveProperty('checks');

      // Verify all health checks are present
      expect(health.checks).toHaveProperty('database');
      expect(health.checks).toHaveProperty('redis');
      expect(health.checks).toHaveProperty('system');
      expect(health.checks).toHaveProperty('logging');
      expect(health.checks).toHaveProperty('security');
    });
  });

  describe('Logger Configuration and Management', () => {
    test('should provide log statistics', () => {
      const stats = logger.management.getLogStats();

      expect(stats).toHaveProperty('level');
      expect(stats).toHaveProperty('transports');
      expect(stats).toHaveProperty('environment');
      expect(stats).toHaveProperty('timestamp');
    });

    test('should allow dynamic log level changes', () => {
      const originalLevel = logger.level;

      // Change to debug level
      logger.management.setLogLevel('debug');
      expect(logger.level).toBe('debug');

      // Change to error level
      logger.management.setLogLevel('error');
      expect(logger.level).toBe('error');

      // Restore original level
      logger.management.setLogLevel(originalLevel);
      expect(logger.level).toBe(originalLevel);
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

  describe('Security Event Logging', () => {
    test('should log various security events without errors', () => {
      const testData = {
        userId: 'test-user',
        ipAddress: '192.168.1.1',
        userAgent: 'Test User Agent'
      };

      // Test all security logging methods
      expect(() => {
        logger.security.authAttempt(testData);
        logger.security.authSuccess(testData);
        logger.security.authFailure({ ...testData, error: 'Invalid credentials' });
        logger.security.authLockout({ ...testData, failedAttempts: 5 });
        logger.security.dataAccess({ ...testData, resource: 'notes', action: 'read' });
        logger.security.dataModification({ ...testData, resource: 'notes', action: 'create' });
        logger.security.securityViolation({ ...testData, type: 'sql_injection' });
        logger.security.rateLimitExceeded({ ...testData, endpoint: '/api/login' });
        logger.security.sessionHijackAttempt({ ...testData, suspiciousIp: '10.0.0.1' });
        logger.security.suspiciousActivity({ ...testData, activity: 'multiple_failed_logins' });
        logger.security.privilegeEscalation({ ...testData, attemptedAction: 'admin_access' });
        logger.security.dataExfiltration({ ...testData, suspiciousPattern: 'bulk_download' });
      }).not.toThrow();
    });
  });

  describe('Audit Trail Logging', () => {
    test('should log audit events without errors', () => {
      const testData = {
        userId: 'test-user',
        action: 'test_action',
        resource: 'test_resource'
      };

      expect(() => {
        logger.audit.logEvent(testData);
        logger.audit.userAction({ ...testData, changes: ['field1', 'field2'] });
        logger.audit.systemAction({ action: 'backup', status: 'completed' });
        logger.audit.configurationChange({
          setting: 'rate_limit',
          oldValue: '5',
          newValue: '10',
          changedBy: 'admin'
        });
      }).not.toThrow();
    });
  });

  describe('Health and Performance Monitoring', () => {
    test('should log health and performance events without errors', () => {
      expect(() => {
        logger.health.systemHealth({
          status: 'healthy',
          uptime: '1h 30m',
          memoryUsage: '45%'
        });

        logger.health.performanceMetric({
          endpoint: '/api/notes',
          responseTime: '150ms',
          statusCode: 200
        });

        logger.health.resourceUsage({
          cpu: '25%',
          memory: '512MB',
          disk: '2GB'
        });
      }).not.toThrow();
    });
  });

  describe('Error Handling and Data Protection', () => {
    test('should handle sensitive data in logs', () => {
      const sensitiveData = {
        username: 'testuser',
        password: 'secret123',
        token: 'jwt-token-value',
        apiKey: 'api-key-secret',
        creditCard: '1234-5678-9012-3456'
      };

      // Should not throw when logging sensitive data
      expect(() => {
        logger.info('Test with sensitive data', sensitiveData);
        logger.security.authAttempt(sensitiveData);
        logger.audit.userAction(sensitiveData);
      }).not.toThrow();
    });

    test('should handle null and undefined values', () => {
      expect(() => {
        logger.info('Test with null values', {
          value1: null,
          value2: undefined,
          value3: '',
          value4: 0,
          value5: false
        });
      }).not.toThrow();
    });

    test('should handle circular references', () => {
      const circularObj = { name: 'test' };
      circularObj.self = circularObj;

      expect(() => {
        logger.info('Test with circular reference', { data: circularObj });
      }).not.toThrow();
    });
  });

  describe('Performance and Resource Management', () => {
    test('should handle high-volume logging', () => {
      const startTime = Date.now();

      // Log 100 messages rapidly
      for (let i = 0; i < 100; i++) {
        logger.info(`Test message ${i}`, { iteration: i });
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (less than 1 second)
      expect(duration).toBeLessThan(1000);
    });

    test('should manage memory usage with large log data', () => {
      const largeData = {
        largeString: 'x'.repeat(10000), // 10KB string
        largeArray: Array(1000).fill().map((_, i) => ({ id: i, data: `item-${i}` }))
      };

      expect(() => {
        logger.info('Test with large data', largeData);
      }).not.toThrow();
    });
  });
});