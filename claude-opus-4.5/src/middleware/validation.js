/**
 * Validation Error Handler
 * Processes express-validator results securely
 */

const { validationResult } = require("express-validator");
const logger = require("../config/logger");

/**
 * Handle validation errors
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    // Log validation failures (for security monitoring)
    logger.warn("Validation failed", {
      path: req.path,
      method: req.method,
      ip: req.ip,
      errors: errors.array().map((e) => ({ field: e.path, msg: e.msg })),
    });

    // Return sanitized error messages (don't leak internal details)
    return res.status(400).json({
      error: "Validation failed",
      details: errors.array().map((err) => ({
        field: err.path,
        message: err.msg,
      })),
    });
  }

  next();
}

module.exports = { handleValidationErrors };
