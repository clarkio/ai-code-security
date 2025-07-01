const jwt = require('jsonwebtoken');
const { AppError } = require('./errorHandler');
const { userStatements, auditStatements } = require('../db/database');
const logger = require('../utils/logger');

// Verify JWT token
async function authenticate(req, res, next) {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AppError('No token provided', 401);
    }
    
    const token = authHeader.substring(7);
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256']
    });
    
    // Check token type
    if (decoded.type !== 'access') {
      throw new AppError('Invalid token type', 401);
    }
    
    // Get user from database
    const user = await userStatements.findById({ id: decoded.userId });
    
    if (!user) {
      throw new AppError('User not found', 401);
    }
    
    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      throw new AppError('Account is locked', 403);
    }
    
    // Attach user to request
    req.user = {
      id: user.id,
      username: user.username,
      email: user.email
    };
    
    // Log successful authentication
    await auditStatements.create({
      user_id: user.id,
      action: 'AUTHENTICATE',
      resource_type: 'AUTH',
      resource_id: null,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      next(new AppError('Invalid token', 401));
    } else if (error.name === 'TokenExpiredError') {
      next(new AppError('Token expired', 401));
    } else {
      next(error);
    }
  }
}

// Optional authentication - doesn't fail if no token
function optionalAuthenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }
  
  // If token is provided, validate it
  authenticate(req, res, next);
}

// Check if user owns the resource
function authorizeOwnership(resourceType) {
  return async (req, res, next) => {
    const resourceId = req.params.id;
    const userId = req.user.id;
    
    // Log authorization attempt
    await auditStatements.create({
      user_id: userId,
      action: 'AUTHORIZE',
      resource_type: resourceType,
      resource_id: resourceId,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    // For notes, check ownership
    if (resourceType === 'NOTE') {
      const { noteStatements } = require('../db/database');
      const note = await noteStatements.findById({ 
        id: resourceId, 
        user_id: userId 
      });
      
      if (!note) {
        throw new AppError('Resource not found or access denied', 404);
      }
      
      req.resource = note;
    }
    
    next();
  };
}

module.exports = {
  authenticate,
  optionalAuthenticate,
  authorizeOwnership
};