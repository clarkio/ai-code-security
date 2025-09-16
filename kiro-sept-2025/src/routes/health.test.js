const request = require('supertest');
const express = require('express');
const healthRoutes = require('./health');
const monitoringService = require('../services/monitoringService');
const logger = require('../utils/logger');

// Mock dependencies
jest.mock('../services/monitoringService');
jest.mock('../utils/logger');

const app = express();
app.use(express.json());
app.use('/health', healthRoutes);

describe('Health Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock logger methods
    logger.error = jest.fn();
    logger.audit = {
      systemAction: jest.fn(),
      configurationChange: jest.fn()
    };
    logger.management = {
      getConfig: jest.fn().mockReturnValue({
        level: 'info',
        environment: 'test',
        logFile: 'logs/test.log',
        transports: [{ type: 'Console', level: 'info' }]
      }),
      getLogStats: jest.fn().mockReturnValue({
        level: 'info',
        transports: 1,
        environment: 'test',
        timestamp: new Date().toISOString()
      }),
      setLogLevel: jest.fn(),
      rotateLogs: jest.fn()
    };
    logger.level = 'info';
  });

  describe('GET /health', () => {
    test('should return healthy status', async () => {
      const mockHealth = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: '1h 30m',
        version: '1.0.0',
        environment: 'test',
        checks: {
          database: { healthy: true },
          redis: { healthy: true },
          system: { healthy: true }
        }
      };

      monitoringService.getHealthStatus.mockResolvedValue(mockHealth);

      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toEqual(mockHealth);
      expect(monitoringService.getHealthStatus).toHaveBeenCalled();
    });

    test('should return degraded status with 200', async () => {
      const mockHealth = {
        status: 'degraded',
        timestamp: new Date().toISOString(),
        uptime: '1h 30m',
        checks: {
          database: { healthy: true },
          redis: { healthy: false },
          system: { healthy: true }
        }
      };

      monitoringService.getHealthStatus.mockResolvedValue(mockHealth);

      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body.status).toBe('degraded');
    });

    test('should return critical status with 503', async () => {
      const mockHealth = {
        status: 'critical',
        timestamp: new Date().toISOString(),
        uptime: '1h 30m',
        checks: {
          database: { healthy: false, critical: true },
          redis: { healthy: false },
          system: { healthy: true }
        }
      };

      monitoringService.getHealthStatus.mockResolvedValue(mockHealth);

      const response = await request(app)
        .get('/health')
        .expect(503);

      expect(response.body.status).toBe('critical');
    });

    test('should handle health check errors', async () => {
      monitoringService.getHealthStatus.mockRejectedValue(new Error('Health check failed'));

      const response = await request(app)
        .get('/health')
        .expect(500);

      expect(response.body.status).toBe('error');
      expect(response.body.message).toBe('Health check failed');
      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('GET /health/detailed', () => {
    test('should return detailed health information', async () => {
      const mockHealth = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        checks: {}
      };

      const mockStats = {
        uptime: '1h 30m',
        healthChecks: {},
        metricsCount: 5,
        alertsCount: 0
      };

      const mockAlerts = [];

      monitoringService.getHealthStatus.mockResolvedValue(mockHealth);
      monitoringService.getMonitoringStats.mockReturnValue(mockStats);
      monitoringService.getAlerts.mockReturnValue(mockAlerts);

      const response = await request(app)
        .get('/health/detailed')
        .expect(200);

      expect(response.body).toHaveProperty('status');
      expect(response.body).toHaveProperty('monitoring');
      expect(response.body.monitoring).toEqual(mockStats);
    });

    test('should include recent alerts when present', async () => {
      const mockHealth = { status: 'healthy' };
      const mockStats = { uptime: '1h' };
      const mockAlerts = [
        { id: '1', type: 'warning', message: 'Test alert' }
      ];

      monitoringService.getHealthStatus.mockResolvedValue(mockHealth);
      monitoringService.getMonitoringStats.mockReturnValue(mockStats);
      monitoringService.getAlerts.mockReturnValue(mockAlerts);

      const response = await request(app)
        .get('/health/detailed')
        .expect(200);

      expect(response.body).toHaveProperty('recentAlerts');
      expect(response.body.recentAlerts).toEqual(mockAlerts);
    });
  });

  describe('GET /health/metrics', () => {
    test('should return application metrics', async () => {
      const mockStats = {
        uptime: '1h 30m',
        healthChecks: {},
        metricsCount: 5,
        alertsCount: 2
      };

      monitoringService.getMonitoringStats.mockReturnValue(mockStats);

      const response = await request(app)
        .get('/health/metrics')
        .expect(200);

      expect(response.body).toHaveProperty('application');
      expect(response.body).toHaveProperty('monitoring');
      expect(response.body).toHaveProperty('logging');
      expect(response.body.application).toHaveProperty('uptime');
      expect(response.body.monitoring).toHaveProperty('metricsCount');
    });

    test('should handle metrics retrieval errors', async () => {
      monitoringService.getMonitoringStats.mockImplementation(() => {
        throw new Error('Metrics error');
      });

      const response = await request(app)
        .get('/health/metrics')
        .expect(500);

      expect(response.body.status).toBe('error');
      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('GET /health/alerts', () => {
    test('should return recent alerts', async () => {
      const mockAlerts = [
        { id: '1', type: 'error', message: 'Database connection failed' },
        { id: '2', type: 'warning', message: 'High memory usage' }
      ];

      monitoringService.getAlerts.mockReturnValue(mockAlerts);

      const response = await request(app)
        .get('/health/alerts')
        .expect(200);

      expect(response.body).toHaveProperty('alerts');
      expect(response.body).toHaveProperty('count');
      expect(response.body.alerts).toEqual(mockAlerts);
      expect(response.body.count).toBe(2);
    });

    test('should respect limit parameter', async () => {
      const mockAlerts = Array(10).fill().map((_, i) => ({
        id: i.toString(),
        type: 'info',
        message: `Alert ${i}`
      }));

      monitoringService.getAlerts.mockReturnValue(mockAlerts.slice(0, 5));

      const response = await request(app)
        .get('/health/alerts?limit=5')
        .expect(200);

      expect(monitoringService.getAlerts).toHaveBeenCalledWith(5);
      expect(response.body.count).toBe(5);
    });

    test('should enforce maximum limit', async () => {
      monitoringService.getAlerts.mockReturnValue([]);

      await request(app)
        .get('/health/alerts?limit=200')
        .expect(200);

      expect(monitoringService.getAlerts).toHaveBeenCalledWith(100); // Max limit
    });
  });

  describe('POST /health/alerts/clear', () => {
    test('should clear old alerts', async () => {
      monitoringService.clearOldAlerts.mockReturnValue(5);

      const response = await request(app)
        .post('/health/alerts/clear')
        .send({ maxAge: 86400000 }) // 24 hours
        .expect(200);

      expect(response.body.message).toBe('Alerts cleared successfully');
      expect(response.body.clearedCount).toBe(5);
      expect(monitoringService.clearOldAlerts).toHaveBeenCalledWith(86400000);
      expect(logger.audit.systemAction).toHaveBeenCalled();
    });

    test('should use default maxAge when not provided', async () => {
      monitoringService.clearOldAlerts.mockReturnValue(3);

      await request(app)
        .post('/health/alerts/clear')
        .send({})
        .expect(200);

      expect(monitoringService.clearOldAlerts).toHaveBeenCalledWith(24 * 60 * 60 * 1000);
    });
  });

  describe('GET /health/logs/config', () => {
    test('should return logging configuration', async () => {
      const response = await request(app)
        .get('/health/logs/config')
        .expect(200);

      expect(response.body).toHaveProperty('configuration');
      expect(response.body).toHaveProperty('statistics');
      expect(response.body).toHaveProperty('timestamp');
      expect(logger.management.getConfig).toHaveBeenCalled();
      expect(logger.management.getLogStats).toHaveBeenCalled();
    });
  });

  describe('PUT /health/logs/level', () => {
    test('should change log level', async () => {
      const response = await request(app)
        .put('/health/logs/level')
        .send({ level: 'debug' })
        .expect(200);

      expect(response.body.message).toBe('Log level updated successfully');
      expect(response.body.oldLevel).toBe('info');
      expect(response.body.newLevel).toBe('debug');
      expect(logger.management.setLogLevel).toHaveBeenCalledWith('debug');
      expect(logger.audit.configurationChange).toHaveBeenCalled();
    });

    test('should return error for missing level', async () => {
      const response = await request(app)
        .put('/health/logs/level')
        .send({})
        .expect(400);

      expect(response.body.status).toBe('error');
      expect(response.body.message).toBe('Log level is required');
    });

    test('should handle invalid log level', async () => {
      logger.management.setLogLevel.mockImplementation(() => {
        throw new Error('Invalid log level: invalid');
      });

      const response = await request(app)
        .put('/health/logs/level')
        .send({ level: 'invalid' })
        .expect(400);

      expect(response.body.status).toBe('error');
      expect(response.body.message).toBe('Invalid log level: invalid');
    });
  });

  describe('POST /health/logs/rotate', () => {
    test('should rotate logs manually', async () => {
      const response = await request(app)
        .post('/health/logs/rotate')
        .expect(200);

      expect(response.body.message).toBe('Log rotation completed successfully');
      expect(logger.management.rotateLogs).toHaveBeenCalled();
      expect(logger.audit.systemAction).toHaveBeenCalledWith({
        action: 'log_rotation_manual',
        requestedBy: 'system'
      });
    });

    test('should handle log rotation errors', async () => {
      logger.management.rotateLogs.mockImplementation(() => {
        throw new Error('Rotation failed');
      });

      const response = await request(app)
        .post('/health/logs/rotate')
        .expect(500);

      expect(response.body.status).toBe('error');
      expect(response.body.message).toBe('Failed to rotate logs');
      expect(logger.error).toHaveBeenCalled();
    });
  });
});