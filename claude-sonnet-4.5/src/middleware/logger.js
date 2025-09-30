/**
 * Request logging middleware
 * Logs requests but sanitizes sensitive information
 */
exports.logger = (req, res, next) => {
  const start = Date.now();

  // Capture response
  const originalSend = res.send;
  res.send = function (data) {
    res.send = originalSend;
    const duration = Date.now() - start;

    // Log request details (sanitize sensitive data)
    const logData = {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get("user-agent"),
      timestamp: new Date().toISOString(),
    };

    // Don't log sensitive data
    if (!req.path.includes("/auth/")) {
      console.log("Request:", logData);
    } else {
      console.log("Auth Request:", {
        method: logData.method,
        path: logData.path,
        statusCode: logData.statusCode,
        duration: logData.duration,
        timestamp: logData.timestamp,
      });
    }

    return res.send(data);
  };

  next();
};
