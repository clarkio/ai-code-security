const fs = require('fs');
const path = require('path');
const winston = require('winston');

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

describe('Logger', () => {
  let logSpy;
  let testTransport;

  beforeEach(() => {
    // Clear any existing transports for clean testing
    logger.clear();
    
    // Create a test transport that captures log output
    const logOutput = [];
    testTransport = new winston.transports.Console({
      format: winston.format.printf((info) => {
        logOutput.push(info);
        return JSON.stringify(info);
      }),
      silent: false
    });
    
    // Add the test transport
    logger.add(testTransport);
    
    // Store reference to log output for assertions
    testTransport.logOutput = logOutput;
  });

  afterEach(() => {
    // Clean up
    if (testTransport && testTransport.logOutput) {
      testTransport.logOutput.length = 0;
    }
  });

  describe('Basic Logging', () => {
    test('should log info messages', () => {
      logger.info('Test info message');
      
      expect(testTransport.logOutput.length).toBeGreaterThan(0);
      expect(testTransport.logOutput.some(log => 
        log.message && log.message.includes('Test info message')
      )).toBe(true);
    });

    test('should log error messages', () => {
      logger.error('Test error message');
      
      expect(testTransport.logOutput.length).toBeGreaterThan(0);
      expect(testTransport.logOutput.some(log => 
        log.message && log.message.includes('Test error message')
      )).toBe(true);
    });

    test('should log warn messages', () => {
      logger.warn('Test warning message');
      
      expect(testTransport.logOutput.length).toBeGreaterThan(0);
      expect(testTransport.logOutput.some(log => 
        log.message && log.message.includes('Test warning message')
      )).toBe(true);
    });
  });

  describe('Sensitive Data Redaction', () => {
    test('should redact password fields', () => {
      const testData = {
        username: 'testuser',
        password: 'secretpassword',
        email: 'test@example.com'
      };

      logger.info('User data', testData);
      
      const logEntry = testTransport.logOutput[testTransport.logOutput.length - 1];
      const logString = JSON.stringify(logEntry);
      
      // Check that password was redacted
      expect(logString).toContain('[REDACTED]');
      
      // Check that password value is not in logs
      expect(logString).not.toContain('secretpassword');
    });

    test('should redact token fields', () => {
      const testData = {
        userId: '123',
        token: 'jwt-token-value',
        refreshToken: 'refresh-token-value'
      };

      logger.info('Token data', testData);
      
      const logEntry = testTransport.logOutput[testTransport.logOutput.length - 1];
      const logString = JSON.stringify(logEntry);
      
      // Check that tokens were redacted
      expect(logString).toContain('[REDACTED]');
      
      // Check that token values are not in logs
      expect(logString).not.toContain('jwt-token-value');
      expect(logString).not.toContain('refresh-token-value');
    });

    test('should redact nested sensitive data', () => {
      const testData = {
        user: {
          id: '123',
          credentials: {
            password: 'secret123',
            apiKey: 'api-key-value'
          }
        }
      };

      logger.info('Nested data', testData);
      
      const logEntry = testTransport.logOutput[testTransport.logOutput.length - 1];
      const logString = JSON.stringify(logEntry);
      
      // Check that nested sensitive data was redacted
      expect(logString).toContain('[REDACTED]');
      
      // Check that sensitive values are not in logs
      expect(logString).not.toContain('secret123');
      expect(logString).not.toContain('api-key-value');
    });

    test('should preserve non-sensitive data', () => {
      const testData = {
        userId: '123',
        username: 'testuser',
        email: 'test@example.com',
        password: 'secret'
      };

      logger.info('Mixed data', testData);
      
      const logEntry = testTransport.logOutput[testTransport.logOutput.length - 1];
      const logString = JSON.stringify(logEntry);
      
      // Check that non-sensitive data is preserved
      expect(logString).toContain('123');
      expect(logString).toContain('testuser');
      expect(logString).toContain('test@example.com');
      
      // But password should be redacted
      expect(logString).not.toContain('secret');
      expect(logString).toContain('[REDACTED]');
    });
  });

  describe('Security Event Logging', () => {
    test('should log authentication attempts', () => {
      const authData = {
        userId: '123',
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0'
      };

      logger.security.authAttempt(authData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Authentication attempt')
        )
      )).toBe(true);
    });

    test('should log authentication success', () => {
      const authData = {
        userId: '123',
        ipAddress: '192.168.1.1'
      };

      logger.security.authSuccess(authData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Authentication successful')
        )
      )).toBe(true);
    });

    test('should log authentication failures', () => {
      const authData = {
        userId: '123',
        reason: 'invalid_password',
        ipAddress: '192.168.1.1'
      };

      logger.security.authFailure(authData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Authentication failed')
        )
      )).toBe(true);
    });

    test('should log account lockouts', () => {
      const lockoutData = {
        userId: '123',
        ipAddress: '192.168.1.1',
        failedAttempts: 5
      };

      logger.security.authLockout(lockoutData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Account locked')
        )
      )).toBe(true);
    });

    test('should log data access events', () => {
      const accessData = {
        userId: '123',
        resource: 'notes',
        action: 'read'
      };

      logger.security.dataAccess(accessData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Data access')
        )
      )).toBe(true);
    });

    test('should log data modification events', () => {
      const modificationData = {
        userId: '123',
        resource: 'notes',
        action: 'update',
        resourceId: 'note-456'
      };

      logger.security.dataModification(modificationData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Data modification')
        )
      )).toBe(true);
    });

    test('should log security violations', () => {
      const violationData = {
        type: 'sql_injection_attempt',
        ipAddress: '192.168.1.1',
        payload: 'SELECT * FROM users'
      };

      logger.security.securityViolation(violationData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Security violation')
        )
      )).toBe(true);
    });

    test('should log rate limit exceeded events', () => {
      const rateLimitData = {
        ipAddress: '192.168.1.1',
        endpoint: '/api/login',
        attempts: 10
      };

      logger.security.rateLimitExceeded(rateLimitData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Rate limit exceeded')
        )
      )).toBe(true);
    });

    test('should log session hijack attempts', () => {
      const hijackData = {
        userId: '123',
        suspiciousIp: '192.168.1.100',
        originalIp: '192.168.1.1'
      };

      logger.security.sessionHijackAttempt(hijackData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Session hijack attempt')
        )
      )).toBe(true);
    });

    test('should log suspicious activity', () => {
      const suspiciousData = {
        userId: '123',
        activity: 'multiple_failed_logins',
        count: 3
      };

      logger.security.suspiciousActivity(suspiciousData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Suspicious activity')
        )
      )).toBe(true);
    });
  });

  describe('Audit Trail Logging', () => {
    test('should log audit events', () => {
      const auditData = {
        userId: '123',
        action: 'note_created',
        resource: 'notes',
        resourceId: 'note-456'
      };

      logger.audit.logEvent(auditData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Audit event')
        )
      )).toBe(true);
    });

    test('should log user actions', () => {
      const actionData = {
        userId: '123',
        action: 'profile_updated',
        changes: ['email', 'name']
      };

      logger.audit.userAction(actionData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('User action audit')
        )
      )).toBe(true);
    });

    test('should log system actions', () => {
      const systemData = {
        action: 'database_backup',
        status: 'completed',
        duration: '5m'
      };

      logger.audit.systemAction(systemData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('System action audit')
        )
      )).toBe(true);
    });

    test('should log configuration changes', () => {
      const configData = {
        setting: 'rate_limit',
        oldValue: '5',
        newValue: '10',
        changedBy: 'admin'
      };

      logger.audit.configurationChange(configData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Configuration change audit')
        )
      )).toBe(true);
    });
  });

  describe('Health and Monitoring', () => {
    test('should log system health checks', () => {
      const healthData = {
        status: 'healthy',
        uptime: '24h',
        memoryUsage: '45%'
      };

      logger.health.systemHealth(healthData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('System health check')
        )
      )).toBe(true);
    });

    test('should log performance metrics', () => {
      const perfData = {
        endpoint: '/api/notes',
        responseTime: '150ms',
        statusCode: 200
      };

      logger.health.performanceMetric(perfData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Performance metric')
        )
      )).toBe(true);
    });

    test('should log resource usage', () => {
      const resourceData = {
        cpu: '25%',
        memory: '512MB',
        disk: '2GB'
      };

      logger.health.resourceUsage(resourceData);
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Resource usage')
        )
      )).toBe(true);
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
      logger.management.setLogLevel('debug');
      expect(logger.level).toBe('debug');
      
      logger.management.setLogLevel('error');
      expect(logger.level).toBe('error');
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
    test('should handle logging errors gracefully', () => {
      // Mock a transport that throws an error
      const errorTransport = new winston.transports.Console({
        format: winston.format.printf(() => {
          throw new Error('Transport error');
        })
      });

      logger.add(errorTransport);
      
      // Should not throw when logging fails
      expect(() => {
        logger.info('Test message');
      }).not.toThrow();
    });

    test('should log structured error objects', () => {
      const error = new Error('Test error');
      error.code = 'TEST_ERROR';
      error.statusCode = 500;

      logger.error('Error occurred', { error });
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('Error occurred')
        )
      )).toBe(true);
    });
  });

  describe('Timestamp and Metadata', () => {
    test('should include timestamps in security events', () => {
      logger.security.authSuccess({ userId: '123' });
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('timestamp')
        )
      )).toBe(true);
    });

    test('should include event types in logs', () => {
      logger.security.dataAccess({ userId: '123', resource: 'notes' });
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('data_access')
        )
      )).toBe(true);
    });

    test('should include severity levels for security events', () => {
      logger.security.securityViolation({ type: 'test_violation' });
      
      expect(logOutput.some(log => 
        log.args.some(arg => 
          typeof arg === 'string' && arg.includes('critical')
        )
      )).toBe(true);
    });
  });
});