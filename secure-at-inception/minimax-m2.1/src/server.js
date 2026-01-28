/**
 * Secure Node.js Notes Application
 * Production-ready with comprehensive security measures
 */
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const config = require('../config.json');
const db = require('./models/database');
const logger = require('./utils/logger');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');
const { setCsrfToken, csrfProtection } = require('./middleware/csrf');

// Import routes
const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');

// Create Express app
const app = express();

// Security Middleware
// 1. Helmet - Sets various HTTP headers for security
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
}));

// 2. CORS - Configure allowed origins
app.use(cors({
  origin: config.cors.origin,
  methods: config.cors.methods,
  allowedHeaders: config.cors.allowedHeaders,
  credentials: config.cors.credentials,
  maxAge: config.cors.maxAge
}));

// 3. Rate Limiting - Prevent brute force attacks
const limiter = rateLimit({
  windowMs: config.security.rateLimit.windowMs,
  max: config.security.rateLimit.max,
  message: {
    error: config.security.rateLimit.message
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use X-Forwarded-For for proxied requests, otherwise use IP
    return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  }
});
app.use('/api/', limiter);

// Additional stricter rate limit for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per 15 minutes
  message: {
    error: 'Too many login attempts, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// 4. Compression - Compress responses
app.use(compression());

// 5. Body parsing with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// 6. Request logging
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.requestLog(req.method, req.path, req.ip, req.userId, res.statusCode, duration);
  });
  
  next();
});

// Health check endpoint (no auth required)
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// API Routes
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/notes', notesRoutes);

// Error handling
app.use(notFoundHandler);
app.use(errorHandler);

// Initialize database and start server
async function startServer() {
  try {
    // Initialize database
    db.initialize();
    
    // Start server
    const port = config.port;
    const server = app.listen(port, () => {
      logger.info(`Server started on port ${port}`);
      logger.info(`Environment: ${config.env}`);
      logger.info(`Health check: http://localhost:${port}/health`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => gracefulShutdown(server));
    process.on('SIGINT', () => gracefulShutdown(server));
    
  } catch (error) {
    logger.error('Failed to start server', { error: error.message });
    process.exit(1);
  }
}

function gracefulShutdown(server) {
  logger.info('Shutting down gracefully...');
  
  server.close(() => {
    logger.info('HTTP server closed');
    db.close();
    process.exit(0);
  });
  
  // Force shutdown after 10 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

// Export app for testing
module.exports = { app, startServer };

// Start server if running directly
if (require.main === module) {
  startServer();
}
