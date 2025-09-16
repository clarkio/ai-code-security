const express = require('express');
const cors = require('cors');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const redis = require('redis');
const path = require('path');

// Import middleware
const {
  helmetConfig,
  authRateLimit,
  apiRateLimit,
  uploadRateLimit,
  corsConfig,
  csrfProtection,
  generateCsrfToken,
  securityLogger,
  sanitizeRequest
} = require('./middleware/security');

const {
  validateRegistration,
  validateLogin,
  validateNoteCreation,
  validateNoteUpdate,
  validatePagination,
  validateFileUploadDefault,
  limitRequestSize
} = require('./middleware/validation');

// Import routes
const notesRoutes = require('./routes/notes');
const healthRoutes = require('./routes/health');

// Import utilities
const logger = require('./utils/logger');
const { validateEnvironment } = require('./config/environment');

// Import database
const databaseInitializer = require('./database/init');

// Validate environment variables on startup (skip in test environment)
if (process.env.NODE_ENV !== 'test') {
  validateEnvironment();
}

const app = express();

// Trust proxy for accurate IP addresses behind reverse proxy
app.set('trust proxy', 1);

// Redis client for session storage (only in production)
let redisClient = null;
let sessionConfig = {
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Don't use default session name
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevent XSS
    maxAge: parseInt(process.env.SESSION_TIMEOUT || '900000'), // 15 minutes default
    sameSite: 'strict' // CSRF protection
  },
  rolling: true // Reset expiration on activity
};

// Use Redis only in production, memory store for development
if (process.env.NODE_ENV === 'production') {
  redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    password: process.env.REDIS_PASSWORD
  });

  redisClient.on('error', (err) => {
    logger.error('Redis connection error', { error: err.message });
  });

  redisClient.on('connect', () => {
    logger.info('Connected to Redis');
  });

  sessionConfig.store = new RedisStore({ client: redisClient });
  logger.info('Using Redis session store');
} else {
  logger.info('Using memory session store for development');
}

// Session configuration
app.use(session(sessionConfig));

// Security middleware - order matters!
app.use(helmetConfig); // Security headers first
app.use(securityLogger); // Log all requests
app.use(sanitizeRequest); // Sanitize input
app.use(limitRequestSize(1024 * 1024)); // 1MB request limit
app.use(cors(corsConfig)); // CORS configuration

// Body parsing middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// CSRF protection setup
app.use(generateCsrfToken); // Generate CSRF tokens
app.use(csrfProtection); // Validate CSRF tokens

// Serve static files with security headers
app.use('/static', express.static(path.join(__dirname, '../public'), {
  maxAge: '1d',
  etag: false,
  setHeaders: (res, path) => {
    // Additional security headers for static files
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'public, max-age=86400');
  }
}));

// Serve HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/register.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

app.get('/notes', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/notes.html'));
});

app.get('/notes/new', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/note-editor.html'));
});

app.get('/notes/edit/:id', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/note-editor.html'));
});

// Health check endpoints (no rate limiting for basic health check)
app.use('/health', healthRoutes);

// API routes with different rate limiting tiers
app.use('/api/auth', authRateLimit); // Strict rate limiting for auth
app.use('/api/upload', uploadRateLimit); // Strict rate limiting for uploads
app.use('/api', apiRateLimit); // General API rate limiting

// Authentication routes (to be implemented)
app.post('/api/auth/register', validateRegistration, (req, res) => {
  // TODO: Implement registration logic
  res.status(501).json({
    error: {
      code: 'NOT_IMPLEMENTED',
      message: 'Registration endpoint not yet implemented',
      timestamp: new Date().toISOString()
    }
  });
});

app.post('/api/auth/login', validateLogin, (req, res) => {
  // TODO: Implement login logic
  res.status(501).json({
    error: {
      code: 'NOT_IMPLEMENTED',
      message: 'Login endpoint not yet implemented',
      timestamp: new Date().toISOString()
    }
  });
});

app.post('/api/auth/logout', (req, res) => {
  // TODO: Implement logout logic
  res.status(501).json({
    error: {
      code: 'NOT_IMPLEMENTED',
      message: 'Logout endpoint not yet implemented',
      timestamp: new Date().toISOString()
    }
  });
});

// Notes routes
app.use('/api/notes', notesRoutes);

// File upload endpoint with validation
app.post('/api/upload', validateFileUploadDefault, (req, res) => {
  // TODO: Implement file upload logic
  res.status(501).json({
    error: {
      code: 'NOT_IMPLEMENTED',
      message: 'File upload endpoint not yet implemented',
      timestamp: new Date().toISOString()
    }
  });
});

// CSRF token endpoint for client-side access
app.get('/api/csrf-token', (req, res) => {
  res.json({
    csrfToken: req.session.csrfToken,
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  logger.warn('404 - Route not found', {
    method: req.method,
    path: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(404).json({
    error: {
      code: 'ROUTE_NOT_FOUND',
      message: 'The requested resource was not found',
      timestamp: new Date().toISOString()
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  // Log the error
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    path: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Don't expose error details in production
  const isDevelopment = process.env.NODE_ENV !== 'production';
  
  res.status(err.status || 500).json({
    error: {
      code: err.code || 'INTERNAL_SERVER_ERROR',
      message: isDevelopment ? err.message : 'An internal server error occurred',
      timestamp: new Date().toISOString(),
      ...(isDevelopment && { stack: err.stack })
    }
  });
});

// Graceful shutdown handling
async function gracefulShutdown(signal) {
  logger.info(`${signal} received, shutting down gracefully`);
  
  try {
    // Close database connection
    const databaseConnection = require('./database/connection');
    await databaseConnection.close();
    logger.info('Database connection closed');
    
    // Close Redis connection if it exists
    if (redisClient) {
      redisClient.quit(() => {
        logger.info('Redis connection closed');
        process.exit(0);
      });
    } else {
      logger.info('No Redis connection to close');
      process.exit(0);
    }
  } catch (error) {
    logger.error('Error during graceful shutdown', { error: error.message });
    process.exit(1);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled promise rejection', { 
    reason: reason?.message || reason,
    promise: promise.toString()
  });
  process.exit(1);
});

const PORT = process.env.PORT || 3000;

// Initialize database and start server
async function startServer() {
  try {
    // Initialize database connection and schema
    await databaseInitializer.initialize();
    logger.info('Database initialized successfully');

    // Only start server if not in test environment
    if (process.env.NODE_ENV !== 'test') {
      app.listen(PORT, () => {
        logger.info(`Secure Notes App listening on port ${PORT}`, {
          environment: process.env.NODE_ENV || 'development',
          port: PORT
        });
      });
    }
  } catch (error) {
    logger.error('Failed to start server', {
      error: error.message,
      stack: error.stack
    });
    process.exit(1);
  }
}

// Start the server
if (process.env.NODE_ENV !== 'test') {
  startServer();
}

module.exports = app;