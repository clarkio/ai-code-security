// Mock the config before requiring logger
jest.mock('../config/environment', () => ({
  app: {
    env: 'test'
  },
  logging: {
    level: 'info',
    file: 'logs/test.log'
  }
}));

const logger = require('./logger');

describe('Logger Core Functionality', () => {
  describe('Logger Structure', () => {
    test('should have security logging methods', () => {
      expect(logger.security).toBeDefined();
      expect(typeof logger.security.authAttempt).toBe('function');
      expect(typeof logger.security.authSuccess).toBe('function');
      expect(typeof logger.security.authFailure).toBe('function');
      expect(typeof logger.security.authLockout).toBe('function');
      expect(typeof logger.security.dataAccess).toBe('function');
      expect(typeof logger.security.dataModification).toBe('function');
      expect(typeof logger.security.securityViolation).toBe('function');
      expect(typeof logger.security.rateLimitExceeded).toBe('function');
    });

    test('should have audit logging methods', () => {
      expect(logger.audit).toBeDefined();
      expect(typeof logger.audit.logEvent).toBe('function');
      expect(typeof logger.audit.userAction).toBe('function');
      expect(typeof logger.audit.systemAction).toBe('function');
      expect(typeof logger.audit.configurationChange).toBe('function');
    });

    test('should have health monitoring methods', () => {
      expect(logger.health).toBeDefined();
      expect(typeof logger.health.systemHealth).toBe('function');
      expect(typeof logger.health.performanceMetric).toBe('function');
      expect(typeof logger.health.resourceUsage).toBe('function');
    });

    test('should have management utilities', () => {
      expect(logger.management).toBeDefined();
      expect(typeof logger.management.getLogStats).toBe('function');
      expect(typeof logger.management.setLogLevel).toBe('function');
      expect(typeof logger.management.getConfig).toBe('function');
    });
  });

  describe('Security Event Logging', () => {
    test('should not throw when logging security events', () => {
      expect(() => {
        logger.security.authAttempt({ userId: '123', ipAddress: '192.168.1.1' });
      }).not.toThrow();

      expect(() => {
        logger.security.authSuccess({ userId: '123', ipAddress: '192.168.1.1' });
      }).not.toThrow();

      expect(() => {
        logger.security.authFailure({ userId: '123', error: 'Invalid password' });
      }).not.toThrow();

      expect(() => {
        logger.security.dataAccess({ userId: '123', resource: 'notes', action: 'read' });
      }).not.toThrow();

      expect(() => {
        logger.security.dataModification({ userId: '123', resource: 'notes', action: 'create' });
      }).not.toThrow();
    });
  });

  describe('Audit Trail Logging', () => {
    test('should not throw when logging audit events', () => {
      expect(() => {
        logger.audit.logEvent({ userId: '123', action: 'note_created', resource: 'notes' });
      }).not.toThrow();

      expect(() => {
        logger.audit.userAction({ userId: '123', action: 'profile_updated' });
      }).not.toThrow();

      expect(() => {
        logger.audit.systemAction({ action: 'database_backup', status: 'completed' });
      }).not.toThrow();
    });
  });

  describe('Health and Monitoring', () => {
    test('should not throw when logging health events', () => {
      expect(() => {
        logger.health.systemHealth({ status: 'healthy', uptime: '1h' });
      }).not.toThrow();

      expect(() => {
        logger.health.performanceMetric({ endpoint: '/api/notes', responseTime: '150ms' });
      }).not.toThrow();

      expect(() => {
        logger.health.resourceUsage({ cpu: '25%', memory: '512MB' });
      }).not.toThrow();
    });
  });

  describe('Log Management', () => {
    test('should get log statistics', () => {
      const stats = logger.management.getLogStats();
      
      expect(stats).toHaveProperty('level');
      expect(stats).toHaveProperty('transports');
      expect(stats).toHaveProperty('environment');
      expect(stats).toHaveProperty('timestamp');
      expect(stats.environment).toBe('test');
    });

    test('should set log level', () => {
      const originalLevel = logger.level;
      
      logger.management.setLogLevel('debug');
      expect(logger.level).toBe('debug');
      
      logger.management.setLogLevel('error');
      expect(logger.level).toBe('error');
      
      // Restore original level
      logger.management.setLogLevel(originalLevel);
    });

    test('should throw error for invalid log level', () => {
      expect(() => {
        logger.management.setLogLevel('invalid');
      }).toThrow('Invalid log level: invalid');
    });

    test('should get current configuration', () => {
      const config = logger.management.getConfig();
      
      expect(config).toHaveProperty('level');
      expect(config).toHaveProperty('environment');
      expect(config).toHaveProperty('logFile');
      expect(config).toHaveProperty('transports');
      expect(Array.isArray(config.transports)).toBe(true);
    });
  });

  describe('Error Handling', () => {
    test('should handle logging with sensitive data', () => {
      expect(() => {
        logger.info('Test with sensitive data', {
          username: 'testuser',
          password: 'secret123',
          token: 'jwt-token-value'
        });
      }).not.toThrow();
    });

    test('should handle logging with nested objects', () => {
      expect(() => {
        logger.info('Test with nested data', {
          user: {
            id: '123',
            credentials: {
              password: 'secret',
              apiKey: 'key-value'
            }
          }
        });
      }).not.toThrow();
    });

    test('should handle logging with null/undefined values', () => {
      expect(() => {
        logger.info('Test with null values', {
          value1: null,
          value2: undefined,
          value3: ''
        });
      }).not.toThrow();
    });
  });

  describe('Logger Metadata', () => {
    test('should have version and initialization metadata', () => {
      expect(logger.version).toBeDefined();
      expect(logger.initialized).toBeDefined();
      expect(typeof logger.version).toBe('string');
      expect(typeof logger.initialized).toBe('string');
    });
  });
});