const monitoringService = require('./monitoringService');
const logger = require('../utils/logger');

// Mock dependencies
jest.mock('../utils/logger');
jest.mock('../database/connection');
jest.mock('redis');
jest.mock('../config/environment', () => ({
  app: { env: 'test' },
  redis: { url: 'redis://localhost:6379' },
  logging: { file: 'logs/test.log' }
}));

describe('MonitoringService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock logger methods
    logger.info = jest.fn();
    logger.warn = jest.fn();
    logger.error = jest.fn();
    logger.health = {
      systemHealth: jest.fn(),
      performanceMetric: jest.fn(),
      resourceUsage: jest.fn()
    };
  });

  describe('Health Status', () => {
    test('should get comprehensive health status', async () => {
      const health = await monitoringService.getHealthStatus();
      
      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('timestamp');
      expect(health).toHaveProperty('uptime');
      expect(health).toHaveProperty('version');
      expect(health).toHaveProperty('environment');
      expect(health).toHaveProperty('checks');
      
      expect(health.checks).toHaveProperty('database');
      expect(health.checks).toHaveProperty('redis');
      expect(health.checks).toHaveProperty('system');
      expect(health.checks).toHaveProperty('logging');
      expect(health.checks).toHaveProperty('security');
    });

    test('should determine overall health status based on checks', async () => {
      const health = await monitoringService.getHealthStatus();
      
      expect(['healthy', 'degraded', 'critical']).toContain(health.status);
    });

    test('should log health check results', async () => {
      await monitoringService.getHealthStatus();
      
      expect(logger.health.systemHealth).toHaveBeenCalledWith(
        expect.objectContaining({
          status: expect.any(String),
          uptime: expect.any(String)
        })
      );
    });
  });

  describe('Database Health Check', () => {
    test('should check database connectivity', async () => {
      const result = await monitoringService.checkDatabaseHealth();
      
      expect(result).toHaveProperty('healthy');
      expect(result).toHaveProperty('timestamp');
      expect(typeof result.healthy).toBe('boolean');
    });

    test('should measure database response time', async () => {
      const result = await monitoringService.checkDatabaseHealth();
      
      if (result.healthy) {
        expect(result).toHaveProperty('responseTime');
        expect(result.responseTime).toMatch(/\d+ms/);
      }
    });

    test('should handle database connection errors', async () => {
      // Mock database connection to throw error
      const databaseConnection = require('../database/connection');
      databaseConnection.query = jest.fn().mockRejectedValue(new Error('Connection failed'));
      
      const result = await monitoringService.checkDatabaseHealth();
      
      expect(result.healthy).toBe(false);
      expect(result.critical).toBe(true);
      expect(result).toHaveProperty('error');
    });
  });

  describe('Redis Health Check', () => {
    test('should check Redis connectivity', async () => {
      const result = await monitoringService.checkRedisHealth();
      
      expect(result).toHaveProperty('healthy');
      expect(result).toHaveProperty('timestamp');
      expect(typeof result.healthy).toBe('boolean');
    });

    test('should handle Redis connection errors', async () => {
      // Mock Redis to throw error
      const redis = require('redis');
      redis.createClient = jest.fn().mockReturnValue({
        connect: jest.fn().mockRejectedValue(new Error('Redis connection failed')),
        quit: jest.fn()
      });
      
      const result = await monitoringService.checkRedisHealth();
      
      expect(result.healthy).toBe(false);
      expect(result.critical).toBe(true);
      expect(result).toHaveProperty('error');
    });
  });

  describe('System Health Check', () => {
    test('should check system resource usage', async () => {
      const result = await monitoringService.checkSystemHealth();
      
      expect(result).toHaveProperty('healthy');
      expect(result).toHaveProperty('memory');
      expect(result).toHaveProperty('cpu');
      expect(result).toHaveProperty('uptime');
      expect(result).toHaveProperty('timestamp');
      
      expect(result.memory).toHaveProperty('heap');
      expect(result.memory).toHaveProperty('system');
      expect(result.cpu).toHaveProperty('loadAverage');
      expect(result.cpu).toHaveProperty('cores');
    });

    test('should log resource usage metrics', async () => {
      await monitoringService.checkSystemHealth();
      
      expect(logger.health.resourceUsage).toHaveBeenCalledWith(
        expect.objectContaining({
          memoryUsagePercent: expect.any(Number),
          systemMemoryPercent: expect.any(Number),
          loadAverage: expect.any(Number),
          uptime: expect.any(String)
        })
      );
    });

    test('should detect high resource usage', async () => {
      // Mock high memory usage
      const originalMemoryUsage = process.memoryUsage;
      process.memoryUsage = jest.fn().mockReturnValue({
        heapUsed: 950 * 1024 * 1024, // 950MB
        heapTotal: 1000 * 1024 * 1024 // 1GB
      });
      
      const result = await monitoringService.checkSystemHealth();
      
      expect(result.healthy).toBe(false);
      
      // Restore original function
      process.memoryUsage = originalMemoryUsage;
    });
  });

  describe('Security Health Check', () => {
    test('should check security metrics', async () => {
      const result = await monitoringService.checkSecurityHealth();
      
      expect(result).toHaveProperty('healthy');
      expect(result).toHaveProperty('metrics');
      expect(result).toHaveProperty('violations');
      expect(result).toHaveProperty('timestamp');
      
      expect(result.metrics).toHaveProperty('failedLogins');
      expect(result.metrics).toHaveProperty('rateLimitHits');
      expect(result.metrics).toHaveProperty('securityViolations');
      expect(result.metrics).toHaveProperty('suspiciousActivity');
    });

    test('should detect security violations', async () => {
      // Set high security violation count
      monitoringService.recordMetric('security_violations_1h', 60);
      
      const result = await monitoringService.checkSecurityHealth();
      
      expect(result.healthy).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
    });
  });

  describe('Metrics Management', () => {
    test('should record metrics', () => {
      const metricName = 'test_metric';
      const metricValue = 42;
      
      monitoringService.recordMetric(metricName, metricValue);
      
      const retrievedValue = monitoringService.getMetric(metricName);
      expect(retrievedValue).toBe(metricValue);
    });

    test('should log performance metrics when recorded', () => {
      monitoringService.recordMetric('response_time', 150);
      
      expect(logger.health.performanceMetric).toHaveBeenCalledWith(
        expect.objectContaining({
          metric: 'response_time',
          value: 150,
          timestamp: expect.any(String)
        })
      );
    });

    test('should aggregate metrics correctly', () => {
      const metricName = 'aggregation_test';
      
      monitoringService.recordMetric(metricName, 10);
      monitoringService.recordMetric(metricName, 20);
      monitoringService.recordMetric(metricName, 30);
      
      expect(monitoringService.getMetric(metricName, 'latest')).toBe(30);
      expect(monitoringService.getMetric(metricName, 'sum')).toBe(60);
      expect(monitoringService.getMetric(metricName, 'average')).toBe(20);
      expect(monitoringService.getMetric(metricName, 'max')).toBe(30);
      expect(monitoringService.getMetric(metricName, 'min')).toBe(10);
    });

    test('should limit metric history', () => {
      const metricName = 'history_test';
      
      // Record more than 1000 metrics
      for (let i = 0; i < 1200; i++) {
        monitoringService.recordMetric(metricName, i);
      }
      
      // Should only keep last 1000
      const metricData = monitoringService.metrics.get(metricName);
      expect(metricData.length).toBe(1000);
      expect(metricData[0].value).toBe(200); // First kept value should be 200
    });
  });

  describe('Alert Management', () => {
    test('should add alerts', () => {
      const alert = {
        type: 'error',
        message: 'Test alert',
        component: 'test'
      };
      
      const addedAlert = monitoringService.addAlert(alert);
      
      expect(addedAlert).toHaveProperty('id');
      expect(addedAlert).toHaveProperty('timestamp');
      expect(addedAlert.type).toBe(alert.type);
      expect(addedAlert.message).toBe(alert.message);
    });

    test('should log alerts when added', () => {
      const alert = {
        type: 'warning',
        message: 'Test warning alert'
      };
      
      monitoringService.addAlert(alert);
      
      expect(logger.error).toHaveBeenCalledWith(
        'Alert generated',
        expect.objectContaining({
          event: 'alert_generated',
          alert: expect.objectContaining({
            type: 'warning',
            message: 'Test warning alert'
          })
        })
      );
    });

    test('should retrieve recent alerts', () => {
      // Add multiple alerts
      for (let i = 0; i < 5; i++) {
        monitoringService.addAlert({
          type: 'info',
          message: `Test alert ${i}`
        });
      }
      
      const alerts = monitoringService.getAlerts(3);
      
      expect(alerts.length).toBe(3);
      expect(alerts[0].message).toBe('Test alert 4'); // Most recent first
    });

    test('should limit alert history', () => {
      // Add more than 100 alerts
      for (let i = 0; i < 150; i++) {
        monitoringService.addAlert({
          type: 'info',
          message: `Alert ${i}`
        });
      }
      
      const allAlerts = monitoringService.getAlerts(200);
      expect(allAlerts.length).toBe(100); // Should only keep last 100
    });

    test('should clear old alerts', () => {
      // Add alerts with old timestamps
      const oldAlert = {
        type: 'info',
        message: 'Old alert',
        timestamp: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString() // 48 hours ago
      };
      
      monitoringService.alerts.push(oldAlert);
      
      const clearedCount = monitoringService.clearOldAlerts(24 * 60 * 60 * 1000); // 24 hours
      
      expect(clearedCount).toBeGreaterThan(0);
    });
  });

  describe('Uptime Calculation', () => {
    test('should calculate uptime correctly', () => {
      const uptime = monitoringService.getUptime();
      
      expect(typeof uptime).toBe('string');
      expect(uptime).toMatch(/\d+[smhd]/); // Should contain time units
    });

    test('should format uptime in human-readable format', () => {
      // Mock start time to be 1 hour ago
      const originalStartTime = monitoringService.startTime;
      monitoringService.startTime = Date.now() - 60 * 60 * 1000; // 1 hour ago
      
      const uptime = monitoringService.getUptime();
      
      expect(uptime).toMatch(/1h/);
      
      // Restore original start time
      monitoringService.startTime = originalStartTime;
    });
  });

  describe('Monitoring Statistics', () => {
    test('should get monitoring statistics', () => {
      const stats = monitoringService.getMonitoringStats();
      
      expect(stats).toHaveProperty('uptime');
      expect(stats).toHaveProperty('healthChecks');
      expect(stats).toHaveProperty('metricsCount');
      expect(stats).toHaveProperty('alertsCount');
      expect(stats).toHaveProperty('timestamp');
      
      expect(typeof stats.uptime).toBe('string');
      expect(typeof stats.metricsCount).toBe('number');
      expect(typeof stats.alertsCount).toBe('number');
    });
  });

  describe('Error Handling', () => {
    test('should handle health check system failures', async () => {
      // Mock a method to throw an error
      const originalCheckSystemHealth = monitoringService.checkSystemHealth;
      monitoringService.checkSystemHealth = jest.fn().mockRejectedValue(new Error('System check failed'));
      
      const health = await monitoringService.getHealthStatus();
      
      expect(health.status).toBe('critical');
      expect(health).toHaveProperty('error');
      
      // Restore original method
      monitoringService.checkSystemHealth = originalCheckSystemHealth;
    });

    test('should handle metric retrieval for non-existent metrics', () => {
      const value = monitoringService.getMetric('non_existent_metric');
      
      expect(value).toBeNull();
    });

    test('should handle invalid aggregation types', () => {
      monitoringService.recordMetric('test_metric', 42);
      
      const value = monitoringService.getMetric('test_metric', 'invalid_aggregation');
      
      expect(value).toBe(42); // Should default to latest
    });
  });
});