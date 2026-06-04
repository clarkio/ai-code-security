require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SequelizeStore = require('connect-session-sequelize')(session.Store);
const compression = require('compression');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

// Import database and models
const { sequelize, syncDatabase } = require('./models');

// Import middleware
const {
  securityHeaders,
  generalLimiter,
  mongoSanitize,
  hpp,
  sanitizeInput,
  generateCSRFToken,
  csrfProtection,
  requestSizeLimit
} = require('./middleware/security');

// Import routes
const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');

const app = express();

// Trust proxy for accurate IP addresses
if (process.env.ENABLE_TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}

// Create logs directory if it doesn't exist
const logsDir = path.dirname(process.env.LOG_FILE || './logs/app.log');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Logging
const logStream = fs.createWriteStream(
  process.env.LOG_FILE || './logs/app.log',
  { flags: 'a' }
);

app.use(morgan('combined', { stream: logStream }));
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Security headers
app.use(securityHeaders);

// Compression
app.use(compression());

// Body parsing with size limit
app.use(express.json({ limit: process.env.MAX_REQUEST_SIZE || '1mb' }));
app.use(express.urlencoded({ extended: true, limit: process.env.MAX_REQUEST_SIZE || '1mb' }));
app.use(requestSizeLimit);

// Cookie parser
app.use(cookieParser());

// Session configuration
const sessionStore = new SequelizeStore({
  db: sequelize,
  checkExpirationInterval: 15 * 60 * 1000, // Clean up expired sessions every 15 minutes
  expiration: parseInt(process.env.SESSION_MAX_AGE) || 3600000 // 1 hour
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: process.env.SESSION_SECURE === 'true', // HTTPS only in production
    httpOnly: process.env.SESSION_HTTP_ONLY !== 'false',
    maxAge: parseInt(process.env.SESSION_MAX_AGE) || 3600000,
    sameSite: process.env.SESSION_SAME_SITE || 'strict'
  },
  name: 'sessionId' // Don't use default name
}));

// Sync session table
sessionStore.sync();

// CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
      : ['http://localhost:3000'];
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  exposedHeaders: ['X-CSRF-Token'],
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// Rate limiting
app.use(generalLimiter);

// Security middleware
app.use(mongoSanitize);
app.use(hpp);
app.use(sanitizeInput);

// Generate CSRF token for all requests
app.use(generateCSRFToken);

// Static files (with security headers)
app.use('/public', express.static(path.join(__dirname, 'public'), {
  dotfiles: 'ignore',
  etag: true,
  extensions: ['html', 'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico'],
  index: false,
  maxAge: '1d',
  redirect: false
}));

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/notes', csrfProtection, notesRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// CSP violation report endpoint
app.post('/csp-report', express.json({ type: 'application/csp-report' }), (req, res) => {
  console.error('CSP Violation:', req.body);
  res.status(204).end();
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    code: 'NOT_FOUND',
    path: req.path
  });
});

// Global error handler
app.use((err, req, res, next) => {
  // Log error
  console.error('Global error handler:', err);

  // CORS error
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      error: 'CORS policy violation',
      code: 'CORS_ERROR'
    });
  }

  // Sequelize validation error
  if (err.name === 'SequelizeValidationError') {
    return res.status(400).json({
      error: 'Validation error',
      code: 'VALIDATION_ERROR',
      errors: err.errors.map(e => ({
        field: e.path,
        message: e.message
      }))
    });
  }

  // Default error response
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    code: 'INTERNAL_ERROR'
  });
});

// Start server
const PORT = process.env.PORT || 3000;

const startServer = async () => {
  try {
    // Sync database
    await syncDatabase();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV}`);
      console.log(`HTTPS only cookies: ${process.env.SESSION_SECURE === 'true'}`);
    });

  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server');
  await sequelize.close();
  process.exit(0);
});

// Start the server
startServer();

module.exports = app;