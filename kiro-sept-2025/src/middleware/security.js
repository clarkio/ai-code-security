const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

/**
 * Configure Helmet.js with strict security headers
 */
const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  frameguard: { action: 'deny' },
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
});

/**
 * Rate limiting configuration for different endpoints
 */
const createRateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    max = 100, // limit each IP to 100 requests per windowMs
    message = 'Too many requests from this IP, please try again later',
    standardHeaders = true,
    legacyHeaders = false,
    skipSuccessfulRequests = false,
    skipFailedRequests = false
  } = options;

  return rateLimit({
    windowMs,
    max,
    message: {
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message,
        retryAfter: Math.ceil(windowMs / 1000),
        timestamp: new Date().toISOString()
      }
    },
    standardHeaders,
    legacyHeaders,
    skipSuccessfulRequests,
    skipFailedRequests,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method
      });

      res.status(429).json({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message,
          retryAfter: Math.ceil(windowMs / 1000),
          timestamp: new Date().toISOString()
        }
      });
    }
  });
};

/**
 * Strict rate limiting for authentication endpoints
 */
const authRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs for auth
  message: 'Too many authentication attempts, please try again later',
  skipSuccessfulRequests: true // Don't count successful requests
});

/**
 * General rate limiting for API endpoints
 */
const apiRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many API requests, please try again later'
});

/**
 * Strict rate limiting for file upload endpoints
 */
const uploadRateLimit = createRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // limit each IP to 10 uploads per hour
  message: 'Too many file uploads, please try again later'
});

/**
 * CORS configuration with restrictive policies
 */
const corsConfig = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.CORS_ORIGIN 
      ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
      : ['http://localhost:3000', 'https://localhost:3000'];
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    logger.warn('CORS policy violation', {
      origin,
      allowedOrigins
    });
    
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-CSRF-Token'
  ],
  exposedHeaders: ['X-CSRF-Token'],
  maxAge: 86400 // 24 hours
};

/**
 * Simple CSRF protection middleware
 * In production, consider using a more robust solution like csurf
 */
const csrfProtection = (req, res, next) => {
  // Skip CSRF for GET, HEAD, OPTIONS requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Skip CSRF for API endpoints using JWT (they have their own protection)
  if (req.path.startsWith('/api/') && req.headers.authorization) {
    return next();
  }

  const token = req.headers['x-csrf-token'] || req.body._csrf;
  const sessionToken = req.session?.csrfToken;

  if (!token || !sessionToken || token !== sessionToken) {
    logger.warn('CSRF token validation failed', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      hasToken: !!token,
      hasSessionToken: !!sessionToken
    });

    return res.status(403).json({
      error: {
        code: 'CSRF_TOKEN_INVALID',
        message: 'Invalid or missing CSRF token',
        timestamp: new Date().toISOString()
      }
    });
  }

  next();
};

/**
 * Generate CSRF token for session
 */
const generateCsrfToken = (req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = require('crypto').randomBytes(32).toString('hex');
  }
  
  // Add token to response headers for client-side access
  res.setHeader('X-CSRF-Token', req.session.csrfToken);
  next();
};

/**
 * Security event logging middleware
 */
const securityLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // Log security-relevant request information
  const logData = {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    method: req.method,
    path: req.path,
    timestamp: new Date().toISOString()
  };

  // Log authentication attempts
  if (req.path.includes('/auth/') || req.path.includes('/login') || req.path.includes('/register')) {
    logger.info('Authentication request', logData);
  }

  // Override res.json to log response status
  const originalJson = res.json;
  res.json = function(data) {
    const responseTime = Date.now() - startTime;
    
    // Log security events based on response
    if (res.statusCode >= 400) {
      logger.warn('Security event - failed request', {
        ...logData,
        statusCode: res.statusCode,
        responseTime,
        error: data?.error?.code
      });
    }

    return originalJson.call(this, data);
  };

  next();
};

/**
 * Request sanitization middleware to prevent common attacks
 */
const sanitizeRequest = (req, res, next) => {
  // Remove null bytes that could be used for path traversal
  const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str.replace(/\0/g, '');
  };

  // Sanitize URL parameters
  if (req.params) {
    Object.keys(req.params).forEach(key => {
      req.params[key] = sanitizeString(req.params[key]);
    });
  }

  // Sanitize query parameters
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (typeof req.query[key] === 'string') {
        req.query[key] = sanitizeString(req.query[key]);
      }
    });
  }

  next();
};

module.exports = {
  helmetConfig,
  authRateLimit,
  apiRateLimit,
  uploadRateLimit,
  corsConfig,
  csrfProtection,
  generateCsrfToken,
  securityLogger,
  sanitizeRequest,
  createRateLimit
};