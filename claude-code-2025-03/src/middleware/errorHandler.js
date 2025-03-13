const createError = require('http-errors');
const config = require('../config');

// 404 Not Found handler
const notFoundHandler = (req, res, next) => {
  next(createError(404, 'Resource not found'));
};

// Global error handler
const errorHandler = (err, req, res, next) => {
  // Set default error code
  const statusCode = err.status || err.statusCode || 500;
  
  // Log error for debugging (not in tests)
  if (process.env.NODE_ENV !== 'test') {
    console.error(`[${new Date().toISOString()}] Error:`, {
      status: statusCode,
      message: err.message,
      stack: config.isDevelopment ? err.stack : undefined,
      path: req.path,
      method: req.method,
    });
  }

  // Format for API responses
  const errorResponse = {
    success: false,
    error: {
      status: statusCode,
      message: err.message || 'Something went wrong',
    },
  };

  // Only include stack trace in development
  if (config.isDevelopment) {
    errorResponse.error.stack = err.stack;
  }

  res.status(statusCode).json(errorResponse);
};

module.exports = {
  notFoundHandler,
  errorHandler,
};