const helmet = require('helmet');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const config = require('../config');

// Configure helmet for security headers
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'same-origin' },
});

// CSRF protection middleware
const csrfProtection = csrf({
  cookie: config.csrfProtection.cookie,
});

// Rate limiting middleware
const apiLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests, please try again later.',
  },
});

// Authentication routes limiter (more strict)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many login attempts, please try again later.',
  },
});

// Middleware to prevent clickjacking
const noFrames = (req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
};

// CSRF error handler
const csrfErrorHandler = (err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  
  // Handle CSRF token errors
  return res.status(403).json({
    success: false,
    message: 'Invalid or expired form submission. Please try again.',
  });
};

module.exports = {
  helmetMiddleware,
  csrfProtection,
  apiLimiter,
  authLimiter,
  noFrames,
  csrfErrorHandler,
};