const express = require('express');
const monitoringService = require('../services/monitoringService');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * GET /health
 * Basic health check endpoint
 */
router.get('/', async (req, res) => {
  try {
    const health = await monitoringService.getHealthStatus();
    
    // Set appropriate HTTP status based on health
    let statusCode = 200;
    if (health.status === 'degraded') {
      statusCode = 200; // Still operational
    } else if (health.status === 'critical') {
      statusCode = 503; // Service unavailable
    }
    
    res.status(statusCode).json(health);
    
  } catch (error) {
    logger.error('Health check endpoint error', {
      error: error.message,
      endpoint: '/health'
    });
    
    res.status(500).json({
      status: 'error',
      message: 'Health check failed',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * GET /health/detailed
 * Detailed health check with all components
 */
router.get('/detailed', async (req, res) => {
  try {
    const health = await monitoringService.getHealthStatus();
    const stats = monitoringService.getMonitoringStats();
    const recentAlerts = monitoringService.getAlerts(10);
    
    const detailedHealth = {
      ...health,
      monitoring: stats,
      recentAlerts: recentAlerts.length > 0 ? recentAlerts : undefined
    };
    
    // Set appropriate HTTP status
    let statusCode = 200;
    if (health.status === 'degraded') {
      statusCode = 200;
    } else if (health.status === 'critical') {
      statusCode = 503;
    }
    
    res.status(statusCode).json(detailedHealth);
    
  } catch (error) {
    logger.error('Detailed health check endpoint error', {
      error: error.message,
      endpoint: '/health/detailed'
    });
    
    res.status(500).json({
      status: 'error',
      message: 'Detailed health check failed',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * GET /health/metrics
 * Get application metrics
 */
router.get('/metrics', (req, res) => {
  try {
    const stats = monitoringService.getMonitoringStats();
    const logConfig = logger.management.getConfig();
    
    const metrics = {
      application: {
        uptime: stats.uptime,
        environment: logConfig.environment,
        logLevel: logConfig.level,
        timestamp: new Date().toISOString()
      },
      monitoring: {
        healthChecks: stats.healthChecks,
        metricsCount: stats.metricsCount,
        alertsCount: stats.alertsCount
      },
      logging: {
        transports: logConfig.transports,
        logFile: logConfig.logFile
      }
    };
    
    res.json(metrics);
    
  } catch (error) {
    logger.error('Metrics endpoint error', {
      error: error.message,
      endpoint: '/health/metrics'
    });
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to retrieve metrics',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * GET /health/alerts
 * Get recent alerts
 */
router.get('/alerts', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const alerts = monitoringService.getAlerts(Math.min(limit, 100)); // Max 100 alerts
    
    res.json({
      alerts,
      count: alerts.length,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    logger.error('Alerts endpoint error', {
      error: error.message,
      endpoint: '/health/alerts'
    });
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to retrieve alerts',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * POST /health/alerts/clear
 * Clear old alerts
 */
router.post('/alerts/clear', (req, res) => {
  try {
    const maxAge = parseInt(req.body.maxAge) || 24 * 60 * 60 * 1000; // 24 hours default
    const clearedCount = monitoringService.clearOldAlerts(maxAge);
    
    logger.audit.systemAction({
      action: 'alerts_cleared',
      clearedCount,
      maxAge,
      requestedBy: req.user?.id || 'system'
    });
    
    res.json({
      message: 'Alerts cleared successfully',
      clearedCount,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    logger.error('Clear alerts endpoint error', {
      error: error.message,
      endpoint: '/health/alerts/clear'
    });
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to clear alerts',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * GET /health/logs/config
 * Get logging configuration
 */
router.get('/logs/config', (req, res) => {
  try {
    const config = logger.management.getConfig();
    const stats = logger.management.getLogStats();
    
    res.json({
      configuration: config,
      statistics: stats,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    logger.error('Log config endpoint error', {
      error: error.message,
      endpoint: '/health/logs/config'
    });
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to retrieve log configuration',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * PUT /health/logs/level
 * Change log level dynamically
 */
router.put('/logs/level', (req, res) => {
  try {
    const { level } = req.body;
    
    if (!level) {
      return res.status(400).json({
        status: 'error',
        message: 'Log level is required',
        timestamp: new Date().toISOString()
      });
    }
    
    const oldLevel = logger.level;
    logger.management.setLogLevel(level);
    
    logger.audit.configurationChange({
      setting: 'log_level',
      oldValue: oldLevel,
      newValue: level,
      changedBy: req.user?.id || 'system'
    });
    
    res.json({
      message: 'Log level updated successfully',
      oldLevel,
      newLevel: level,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    logger.error('Change log level endpoint error', {
      error: error.message,
      endpoint: '/health/logs/level',
      requestedLevel: req.body.level
    });
    
    res.status(400).json({
      status: 'error',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * POST /health/logs/rotate
 * Manually rotate logs
 */
router.post('/logs/rotate', (req, res) => {
  try {
    logger.management.rotateLogs();
    
    logger.audit.systemAction({
      action: 'log_rotation_manual',
      requestedBy: req.user?.id || 'system'
    });
    
    res.json({
      message: 'Log rotation completed successfully',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    logger.error('Log rotation endpoint error', {
      error: error.message,
      endpoint: '/health/logs/rotate'
    });
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to rotate logs',
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;