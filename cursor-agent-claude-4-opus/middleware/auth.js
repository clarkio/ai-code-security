const jwt = require('jsonwebtoken');
const { User } = require('../models');

// Verify JWT token
const verifyToken = async (req, res, next) => {
  try {
    // Get token from Authorization header or session
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : req.session?.token;

    if (!token) {
      return res.status(401).json({ 
        error: 'Access denied. No token provided.',
        code: 'NO_TOKEN'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if user still exists and is active
    const user = await User.findByPk(decoded.id);
    
    if (!user || !user.is_active) {
      return res.status(401).json({ 
        error: 'Invalid token. User not found or inactive.',
        code: 'INVALID_USER'
      });
    }

    // Check if password was changed after token was issued
    if (user.password_changed_at) {
      const passwordChangedAt = Math.floor(user.password_changed_at.getTime() / 1000);
      if (decoded.iat < passwordChangedAt) {
        return res.status(401).json({ 
          error: 'Password has been changed. Please login again.',
          code: 'PASSWORD_CHANGED'
        });
      }
    }

    // Attach user to request
    req.user = user;
    req.userId = user.id;
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        error: 'Invalid token.',
        code: 'INVALID_TOKEN'
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token has expired.',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    console.error('Auth middleware error:', error);
    return res.status(500).json({ 
      error: 'Internal server error during authentication.',
      code: 'AUTH_ERROR'
    });
  }
};

// Optional auth - doesn't fail if no token
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : req.session?.token;

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findByPk(decoded.id);
      
      if (user && user.is_active) {
        req.user = user;
        req.userId = user.id;
      }
    }
  } catch (error) {
    // Silently continue without user
  }
  
  next();
};

// Check if user owns the resource
const checkOwnership = (resourceGetter) => {
  return async (req, res, next) => {
    try {
      const resource = await resourceGetter(req);
      
      if (!resource) {
        return res.status(404).json({ 
          error: 'Resource not found.',
          code: 'NOT_FOUND'
        });
      }

      if (resource.user_id !== req.userId) {
        return res.status(403).json({ 
          error: 'Access denied. You do not own this resource.',
          code: 'FORBIDDEN'
        });
      }

      req.resource = resource;
      next();
    } catch (error) {
      console.error('Ownership check error:', error);
      return res.status(500).json({ 
        error: 'Internal server error during ownership check.',
        code: 'OWNERSHIP_CHECK_ERROR'
      });
    }
  };
};

module.exports = {
  verifyToken,
  optionalAuth,
  checkOwnership
};