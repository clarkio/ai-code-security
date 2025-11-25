/**
 * Error Handler Middleware
 * Centralized error handling with secure error messages
 */

const logger = require("../config/logger");
const config = require("../config");

/**
 * Not Found Handler
 */
function notFoundHandler(req, res) {
  res.status(404).json({
    error: "Resource not found",
    path: req.path,
  });
}

/**
 * Global Error Handler
 * Never expose stack traces or internal details in production
 */
function errorHandler(err, req, res, _next) {
  // Log full error details
  logger.error("Unhandled error:", {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
  });

  // Handle specific error types
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      error: "Invalid JSON payload",
    });
  }

  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({
      error: "Invalid or missing CSRF token",
    });
  }

  if (err.message === "Not allowed by CORS") {
    return res.status(403).json({
      error: "Origin not allowed",
    });
  }

  // Default error response
  const statusCode = err.statusCode || err.status || 500;

  // In production, never expose internal error details
  const response = {
    error:
      statusCode >= 500
        ? "An internal server error occurred"
        : err.message || "An error occurred",
  };

  // Include error details only in development
  if (config.env === "development") {
    response.details = err.message;
    response.stack = err.stack;
  }

  res.status(statusCode).json(response);
}

module.exports = {
  notFoundHandler,
  errorHandler,
};
