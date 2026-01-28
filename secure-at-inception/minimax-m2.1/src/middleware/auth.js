/**
 * JWT Authentication Middleware
 * Provides secure token-based authentication
 */
const jwt = require('jsonwebtoken');
const config = require('../config/default.json');
const logger = require('../utils/logger');

/**
 * Generate JWT token for user
 */
function generateToken(userId) {
  return jwt.sign(
    { userId },
    config.security.jwt.secret,
    {
      algorithm: config.security.jwt.algorithm,
      expiresIn: config.security.jwt.expiresIn
    }
  );
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, config.security.jwt.secret, {
      algorithms: [config.security.jwt.algorithm]
    });
  } catch (error) {
    logger.securityEvent('jwt_verification_failed', { error: error.message });
    return null;
  }
}

/**
 * Authentication middleware
 */
function authenticate(req, res, next) {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'No authorization token provided'
      });
    }

    // Check Bearer token format
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Invalid authorization format',
        message: 'Authorization header must use Bearer scheme'
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    if (!token) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'Token is empty'
      });
    }

    // Verify token
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'Token is invalid or expired'
      });
    }

    // Attach user info to request
    req.userId = decoded.userId;
    req.token = token;

    next();
  } catch (error) {
    logger.error('Authentication error', { error: error.message });
    return res.status(500).json({
      error: 'Authentication error',
      message: 'An error occurred during authentication'
    });
  }
}

/**
 * Optional authentication (doesn't fail if no token)
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const decoded = verifyToken(token);
    
    if (decoded) {
      req.userId = decoded.userId;
      req.token = token;
    }
  }
  
  next();
}

module.exports = {
  generateToken,
  verifyToken,
  authenticate,
  optionalAuth
};
