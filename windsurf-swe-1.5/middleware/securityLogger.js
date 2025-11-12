/**
 * Security logging middleware
 */
const securityLogger = (logger) => (req, res, next) => {
  // Log suspicious activities
  const suspiciousPatterns = [
    /\.\./,  // Directory traversal
    /<script/i,  // XSS attempt
    /javascript:/i,  // JavaScript protocol
    /union.*select/i,  // SQL injection attempt
    /drop.*table/i,  // SQL injection attempt
  ];

  const isSuspicious = suspiciousPatterns.some(pattern => 
    pattern.test(req.url) || 
    pattern.test(JSON.stringify(req.body)) ||
    pattern.test(JSON.stringify(req.query))
  );

  if (isSuspicious) {
    logger.warn('Suspicious request detected:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.url,
      method: req.method,
      body: req.body,
      query: req.query,
      timestamp: new Date().toISOString()
    });
  }

  // Log all API requests in production
  if (process.env.NODE_ENV === 'production' && req.url.startsWith('/api/')) {
    logger.info('API request:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.url,
      method: req.method,
      timestamp: new Date().toISOString()
    });
  }

  next();
};

module.exports = securityLogger;
