/**
 * Authentication middleware functions
 */

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required',
    });
  }
  next();
};

// Middleware to ensure user is not authenticated
const isNotAuthenticated = (req, res, next) => {
  if (req.session && req.session.user) {
    return res.status(403).json({
      success: false,
      message: 'Already authenticated',
    });
  }
  next();
};

// Middleware to verify user owns the resource
const isResourceOwner = (req, res, next) => {
  // The userId from the authenticated session
  const userId = req.session.user.id.toString();
  
  // The userId from the requested resource (set by controller)
  const resourceUserId = req.resourceUserId ? req.resourceUserId.toString() : null;
  
  if (!resourceUserId || userId !== resourceUserId) {
    return res.status(403).json({
      success: false,
      message: 'Access denied',
    });
  }
  
  next();
};

module.exports = {
  isAuthenticated,
  isNotAuthenticated,
  isResourceOwner,
};