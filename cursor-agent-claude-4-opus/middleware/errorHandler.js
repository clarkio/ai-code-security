const logger = require('../utils/logger');

// Custom error class
class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Error handler middleware
function errorHandler(err, req, res, next) {
  // Log error details
  logger.error('Error occurred:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userId: req.user?.id
  });

  // Default error values
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal server error';
  let isOperational = err.isOperational || false;

  // Handle specific error types
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Invalid input data';
    isOperational = true;
  } else if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
    isOperational = true;
  } else if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
    isOperational = true;
  } else if (err.name === 'UnauthorizedError') {
    statusCode = 401;
    message = 'Unauthorized access';
    isOperational = true;
  } else if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
    statusCode = 409;
    message = 'Resource already exists';
    isOperational = true;
  } else if (err.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
    statusCode = 400;
    message = 'Invalid reference';
    isOperational = true;
  }

  // In production, don't expose internal error details
  if (process.env.NODE_ENV === 'production' && !isOperational) {
    message = 'An error occurred processing your request';
  }

  // Send error response
  res.status(statusCode).json({
    error: message,
    ...(process.env.NODE_ENV !== 'production' && {
      stack: err.stack,
      details: err
    })
  });
}

// Async error wrapper
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Not found handler
function notFoundHandler(req, res, next) {
  const error = new AppError('Resource not found', 404);
  next(error);
}

module.exports = {
  AppError,
  errorHandler,
  asyncHandler,
  notFoundHandler
};