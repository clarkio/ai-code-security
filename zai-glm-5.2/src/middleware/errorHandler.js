"use strict";

/**
 * Centralized error handler.
 *
 * SECURITY: Never leak stack traces or internal error details to clients.
 * In production, return a generic message. Log full error server-side only.
 */

const config = require("../config/env");

// 404 handler
function notFound(req, res) {
  if (req.accepts("html")) {
    return res.status(404).render("error", {
      title: "Not Found",
      message: "The page you requested does not exist.",
      statusCode: 404,
    });
  }
  return res.status(404).json({ error: "Not found" });
}

// Generic error handler (must have 4 args for Express to recognize it)
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  // Log full error server-side
  console.error(`[ERROR] ${req.method} ${req.path}:`, err);

  const statusCode = err.statusCode || 500;
  const message = config.isProduction
    ? statusCode === 500
      ? "Internal server error"
      : err.message
    : err.message;

  if (req.accepts("html")) {
    return res.status(statusCode).render("error", {
      title: "Error",
      message,
      statusCode,
    });
  }
  return res.status(statusCode).json({ error: message });
}

module.exports = { notFound, errorHandler };
