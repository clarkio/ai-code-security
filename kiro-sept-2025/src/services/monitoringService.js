const logger = require('../utils/logger');
const databaseConnection = require('../database/connection');
const redis = require('redis');
const config = require('../config/environment');
const os = require('os');
const fs = require('fs').promises;
const path = require('path');

class MonitoringService {
  constructor() {
    this.startTime = Date.now();
    this.healthChecks = new Map();
    this.metrics = new Map();
    this.alerts = [];
    
    // Initialize health check intervals
    this.initializeHealthChecks();
  }

  /**
   * Initialize periodic health checks
   */
  initializeHealthChecks() {
    // Database health check every 30 seconds
    setInterval(() => {
      this.checkDatabaseHealth();
    }, 30000);

    // Redis health check every 30 seconds
    setInterval(() => {
      this.checkRedisHealth();
    }, 30000);

    // System health check every 60 seconds
    setInterval(() => {
      this.checkSystemHealth();
    }, 60000);

    // Log file health check every 5 minutes
    setInterval(() => {
      this.checkLogFileHealth();
    }, 300000);

    logger.info('Health check intervals initialized', {
      event: 'monitoring_initialized',
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Get comprehensive application health status
   */
  async getHealthStatus() {
    try {
      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: this.getUptime(),
        version: process.env.npm_package_version || '1.0.0',
        environment: config.app.env,
        checks: {}
      };

      // Perform all health checks
      health.checks.database = await this.checkDatabaseHealth();
      health.checks.redis = await this.checkRedisHealth();
      health.checks.system = await this.checkSystemHealth();
      health.checks.logging = await this.checkLogFileHealth();
      health.checks.security = await this.checkSecurityHealth();

      // Determine overall health status
      const failedChecks = Object.values(health.checks).filter(check => !check.healthy);
      
      if (failedChecks.length > 0) {
        health.status = failedChecks.some(check => check.critical) ? 'critical' : 'degraded';
      }

      // Log health check results
      logger.health.systemHealth({
        status: health.status,
        failedChecks: failedChecks.length,
        uptime: health.uptime
      });

      return health;

    } catch (error) {
      logger.error('Health check failed', {
        error: error.message,
        timestamp: new Date().toISOString()
      });

      return {
        status: 'critical',
        timestamp: new Date().toISOString(),
        error: 'Health check system failure',
        uptime: this.getUptime()
      };
    }
  }

  /**
   * Check database connectivity and performance
   */
  async checkDatabaseHealth() {
    try {
      const startTime = Date.now();
      
      // Simple connectivity test
      await databaseConnection.query('SELECT 1');
      
      const responseTime = Date.now() - startTime;
      
      // Check connection pool status
      const poolStatus = {
        totalConnections: databaseConnection.totalCount || 0,
        idleConnections: databaseConnection.idleCount || 0,
        waitingClients: databaseConnection.waitingCount || 0
      };

      const healthy = responseTime < 1000; // Consider healthy if response < 1s
      
      const result = {
        healthy,
        responseTime: `${responseTime}ms`,
        poolStatus,
        timestamp: new Date().toISOString(),
        critical: !healthy && responseTime > 5000 // Critical if > 5s
      };

      if (!healthy) {
        logger.warn('Database health check failed', {
          event: 'health_check_failed',
          component: 'database',
          responseTime,
          poolStatus
        });
      }

      this.healthChecks.set('database', result);
      return result;

    } catch (error) {
      const result = {
        healthy: false,
        critical: true,
        error: error.message,
        timestamp: new Date().toISOString()
      };

      logger.error('Database health check error', {
        event: 'health_check_error',
        component: 'database',
        error: error.message
      });

      this.healthChecks.set('database', result);
      return result;
    }
  }

  /**
   * Check Redis connectivity and performance
   */
  async checkRedisHealth() {
    // Skip Redis health check in development mode
    if (config.app.env !== 'production') {
      const result = {
        healthy: true,
        status: 'skipped',
        reason: 'Redis not used in development mode',
        timestamp: new Date().toISOString(),
        critical: false
      };

      this.healthChecks.set('redis', result);
      return result;
    }

    let client;
    
    try {
      const startTime = Date.now();
      
      // Create temporary Redis client for health check
      client = redis.createClient({
        url: config.redis.url,
        password: config.redis.password
      });

      await client.connect();
      
      // Test basic operations
      await client.ping();
      await client.set('health_check', 'ok', { EX: 10 });
      const value = await client.get('health_check');
      
      const responseTime = Date.now() - startTime;
      const healthy = responseTime < 500 && value === 'ok';
      
      const result = {
        healthy,
        responseTime: `${responseTime}ms`,
        timestamp: new Date().toISOString(),
        critical: !healthy && responseTime > 2000
      };

      if (!healthy) {
        logger.warn('Redis health check failed', {
          event: 'health_check_failed',
          component: 'redis',
          responseTime
        });
      }

      this.healthChecks.set('redis', result);
      return result;

    } catch (error) {
      const result = {
        healthy: false,
        critical: true,
        error: error.message,
        timestamp: new Date().toISOString()
      };

      logger.error('Redis health check error', {
        event: 'health_check_error',
        component: 'redis',
        error: error.message
      });

      this.healthChecks.set('redis', result);
      return result;

    } finally {
      if (client) {
        try {
          await client.quit();
        } catch (error) {
          // Ignore cleanup errors
        }
      }
    }
  }

  /**
   * Check system resource usage
   */
  async checkSystemHealth() {
    try {
      const memoryUsage = process.memoryUsage();
      const systemMemory = {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem()
      };

      const cpuUsage = process.cpuUsage();
      const loadAverage = os.loadavg();

      const memoryUsagePercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
      const systemMemoryPercent = (systemMemory.used / systemMemory.total) * 100;

      const healthy = memoryUsagePercent < 90 && systemMemoryPercent < 90 && loadAverage[0] < os.cpus().length * 2;

      const result = {
        healthy,
        memory: {
          heap: {
            used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
            total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
            percent: `${Math.round(memoryUsagePercent)}%`
          },
          system: {
            used: `${Math.round(systemMemory.used / 1024 / 1024)}MB`,
            total: `${Math.round(systemMemory.total / 1024 / 1024)}MB`,
            percent: `${Math.round(systemMemoryPercent)}%`
          }
        },
        cpu: {
          loadAverage: loadAverage.map(load => Math.round(load * 100) / 100),
          cores: os.cpus().length
        },
        uptime: this.getUptime(),
        timestamp: new Date().toISOString(),
        critical: memoryUsagePercent > 95 || systemMemoryPercent > 95
      };

      if (!healthy) {
        logger.warn('System health check failed', {
          event: 'health_check_failed',
          component: 'system',
          memoryUsagePercent,
          systemMemoryPercent,
          loadAverage: loadAverage[0]
        });
      }

      // Log resource usage metrics
      logger.health.resourceUsage({
        memoryUsagePercent: Math.round(memoryUsagePercent),
        systemMemoryPercent: Math.round(systemMemoryPercent),
        loadAverage: loadAverage[0],
        uptime: this.getUptime()
      });

      this.healthChecks.set('system', result);
      return result;

    } catch (error) {
      const result = {
        healthy: false,
        critical: false,
        error: error.message,
        timestamp: new Date().toISOString()
      };

      logger.error('System health check error', {
        event: 'health_check_error',
        component: 'system',
        error: error.message
      });

      this.healthChecks.set('system', result);
      return result;
    }
  }

  /**
   * Check log file health and disk usage
   */
  async checkLogFileHealth() {
    try {
      const logDir = path.dirname(config.logging.file);
      const logFiles = ['app.log', 'error.log', 'security.log', 'audit.log'];
      
      const fileStats = {};
      let totalLogSize = 0;

      for (const logFile of logFiles) {
        const filePath = path.join(logDir, logFile);
        
        try {
          const stats = await fs.stat(filePath);
          fileStats[logFile] = {
            size: `${Math.round(stats.size / 1024 / 1024 * 100) / 100}MB`,
            modified: stats.mtime.toISOString()
          };
          totalLogSize += stats.size;
        } catch (error) {
          fileStats[logFile] = {
            error: 'File not found or inaccessible'
          };
        }
      }

      // Check if log directory is writable
      const testFile = path.join(logDir, 'write-test.tmp');
      let writable = true;
      
      try {
        await fs.writeFile(testFile, 'test');
        await fs.unlink(testFile);
      } catch (error) {
        writable = false;
      }

      const totalLogSizeMB = totalLogSize / 1024 / 1024;
      const healthy = writable && totalLogSizeMB < 1000; // Healthy if < 1GB total logs

      const result = {
        healthy,
        writable,
        totalSize: `${Math.round(totalLogSizeMB * 100) / 100}MB`,
        files: fileStats,
        timestamp: new Date().toISOString(),
        critical: !writable || totalLogSizeMB > 5000 // Critical if > 5GB
      };

      if (!healthy) {
        logger.warn('Log file health check failed', {
          event: 'health_check_failed',
          component: 'logging',
          writable,
          totalLogSizeMB
        });
      }

      this.healthChecks.set('logging', result);
      return result;

    } catch (error) {
      const result = {
        healthy: false,
        critical: false,
        error: error.message,
        timestamp: new Date().toISOString()
      };

      logger.error('Log file health check error', {
        event: 'health_check_error',
        component: 'logging',
        error: error.message
      });

      this.healthChecks.set('logging', result);
      return result;
    }
  }

  /**
   * Check security-related health metrics
   */
  async checkSecurityHealth() {
    try {
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

      // This would typically query audit logs or security metrics
      // For now, we'll simulate security health checks
      
      const securityMetrics = {
        failedLogins: this.getMetric('failed_logins_1h') || 0,
        rateLimitHits: this.getMetric('rate_limit_hits_1h') || 0,
        securityViolations: this.getMetric('security_violations_1h') || 0,
        suspiciousActivity: this.getMetric('suspicious_activity_1h') || 0
      };

      // Define thresholds for security health
      const thresholds = {
        failedLogins: 100,
        rateLimitHits: 500,
        securityViolations: 10,
        suspiciousActivity: 20
      };

      const violations = Object.entries(securityMetrics)
        .filter(([key, value]) => value > thresholds[key])
        .map(([key, value]) => ({ metric: key, value, threshold: thresholds[key] }));

      const healthy = violations.length === 0;

      const result = {
        healthy,
        metrics: securityMetrics,
        violations,
        timestamp: new Date().toISOString(),
        critical: violations.some(v => v.metric === 'securityViolations' && v.value > 50)
      };

      if (!healthy) {
        logger.warn('Security health check failed', {
          event: 'health_check_failed',
          component: 'security',
          violations
        });
      }

      this.healthChecks.set('security', result);
      return result;

    } catch (error) {
      const result = {
        healthy: false,
        critical: false,
        error: error.message,
        timestamp: new Date().toISOString()
      };

      logger.error('Security health check error', {
        event: 'health_check_error',
        component: 'security',
        error: error.message
      });

      this.healthChecks.set('security', result);
      return result;
    }
  }

  /**
   * Record a metric value
   */
  recordMetric(name, value, timestamp = new Date()) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }

    const metricData = this.metrics.get(name);
    metricData.push({ value, timestamp });

    // Keep only last 1000 entries per metric
    if (metricData.length > 1000) {
      metricData.splice(0, metricData.length - 1000);
    }

    // Log performance metrics
    logger.health.performanceMetric({
      metric: name,
      value,
      timestamp: timestamp.toISOString()
    });
  }

  /**
   * Get metric value (latest or aggregated)
   */
  getMetric(name, aggregation = 'latest') {
    const metricData = this.metrics.get(name);
    
    if (!metricData || metricData.length === 0) {
      return null;
    }

    switch (aggregation) {
      case 'latest':
        return metricData[metricData.length - 1].value;
      case 'sum':
        return metricData.reduce((sum, entry) => sum + entry.value, 0);
      case 'average':
        return metricData.reduce((sum, entry) => sum + entry.value, 0) / metricData.length;
      case 'max':
        return Math.max(...metricData.map(entry => entry.value));
      case 'min':
        return Math.min(...metricData.map(entry => entry.value));
      default:
        return metricData[metricData.length - 1].value;
    }
  }

  /**
   * Get application uptime in human-readable format
   */
  getUptime() {
    const uptimeMs = Date.now() - this.startTime;
    const uptimeSeconds = Math.floor(uptimeMs / 1000);
    
    const days = Math.floor(uptimeSeconds / 86400);
    const hours = Math.floor((uptimeSeconds % 86400) / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;

    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m ${seconds}s`;
    } else if (hours > 0) {
      return `${hours}h ${minutes}m ${seconds}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Get monitoring statistics
   */
  getMonitoringStats() {
    return {
      uptime: this.getUptime(),
      healthChecks: Object.fromEntries(this.healthChecks),
      metricsCount: this.metrics.size,
      alertsCount: this.alerts.length,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Add an alert
   */
  addAlert(alert) {
    const alertWithTimestamp = {
      ...alert,
      id: Date.now().toString(),
      timestamp: new Date().toISOString()
    };

    this.alerts.push(alertWithTimestamp);

    // Keep only last 100 alerts
    if (this.alerts.length > 100) {
      this.alerts.splice(0, this.alerts.length - 100);
    }

    logger.error('Alert generated', {
      event: 'alert_generated',
      alert: alertWithTimestamp
    });

    return alertWithTimestamp;
  }

  /**
   * Get recent alerts
   */
  getAlerts(limit = 50) {
    return this.alerts
      .slice(-limit)
      .reverse(); // Most recent first
  }

  /**
   * Clear old alerts
   */
  clearOldAlerts(maxAge = 24 * 60 * 60 * 1000) { // 24 hours default
    const cutoff = new Date(Date.now() - maxAge);
    
    const originalCount = this.alerts.length;
    this.alerts = this.alerts.filter(alert => new Date(alert.timestamp) > cutoff);
    
    const clearedCount = originalCount - this.alerts.length;
    
    if (clearedCount > 0) {
      logger.info('Cleared old alerts', {
        event: 'alerts_cleared',
        clearedCount,
        remainingCount: this.alerts.length
      });
    }

    return clearedCount;
  }
}

// Create singleton instance
const monitoringService = new MonitoringService();

module.exports = monitoringService;