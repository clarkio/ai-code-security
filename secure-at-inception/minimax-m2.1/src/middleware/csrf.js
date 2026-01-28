/**
 * CSRF Protection Middleware
 * Provides CSRF protection for state-changing operations
 */
const crypto = require('crypto');

/**
 * Generate a secure CSRF token
 */
function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Verify CSRF token
 */
function verifyCsrfToken(token, expectedToken) {
  if (!token || !expectedToken) {
    return false;
  }
  
  // Use timing-safe comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(token),
      Buffer.from(expectedToken)
    );
  } catch {
    return false;
  }
}

/**
 * CSRF protection middleware
 * Validates X-CSRF-Token header against stored token
 */
function csrfProtection(req, res, next) {
  // Skip CSRF for safe methods and health check
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  // Get token from header
  const csrfToken = req.headers['x-csrf-token'];
  
  if (!csrfToken) {
    return res.status(403).json({
      error: 'CSRF validation failed',
      message: 'Missing CSRF token'
    });
  }

  // Get expected token from session/cookie
  const expectedToken = req.csrfToken;
  
  if (!expectedToken) {
    return res.status(403).json({
      error: 'CSRF validation failed',
      message: 'No CSRF token in session'
    });
  }

  // Verify token
  if (!verifyCsrfToken(csrfToken, expectedToken)) {
    return res.status(403).json({
      error: 'CSRF validation failed',
      message: 'Invalid CSRF token'
    });
  }

  next();
}

/**
 * Set CSRF token in response
 */
function setCsrfToken(req, res, next) {
  // Generate token if not exists
  if (!req.csrfToken) {
    req.csrfToken = generateCsrfToken();
  }
  
  // Set token in response header for client to use
  res.setHeader('X-CSRF-Token', req.csrfToken);
  
  next();
}

module.exports = {
  generateCsrfToken,
  verifyCsrfToken,
  csrfProtection,
  setCsrfToken
};
