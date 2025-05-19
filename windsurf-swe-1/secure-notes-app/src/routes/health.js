const express = require('express');
const mongoose = require('mongoose');
const { StatusCodes } = require('http-status-codes');

const router = express.Router();

// Health check endpoint
router.get('/', async (req, res) => {
  // Check database connection
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  
  // Check memory usage
  const memoryUsage = process.memoryUsage();
  const memoryUsageInMB = {
    rss: Math.round((memoryUsage.rss / 1024 / 1024) * 100) / 100,
    heapTotal: Math.round((memoryUsage.heapTotal / 1024 / 1024) * 100) / 100,
    heapUsed: Math.round((memoryUsage.heapUsed / 1024 / 1024) * 100) / 100,
    external: Math.round((memoryUsage.external / 1024 / 1024) * 100) / 100,
  };

  // Uptime in seconds
  const uptime = process.uptime();
  
  // Prepare response
  const healthCheck = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(uptime / 60 / 60)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`,
    database: dbStatus,
    memory: memoryUsageInMB,
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
  };

  // Set response status based on database connection
  const statusCode = dbStatus === 'connected' ? StatusCodes.OK : StatusCodes.SERVICE_UNAVAILABLE;
  
  res.status(statusCode).json(healthCheck);
});

module.exports = router;
