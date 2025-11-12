const DOMPurify = require('isomorphic-dompurify');

/**
 * Sanitize HTML content to prevent XSS attacks
 */
const sanitizeHtml = (content) => {
  if (typeof content !== 'string') {
    return content;
  }
  
  return DOMPurify.sanitize(content, {
    ALLOWED_TAGS: [], // No HTML tags allowed
    ALLOWED_ATTR: [], // No attributes allowed
    KEEP_CONTENT: true // Keep text content
  });
};

/**
 * Sanitize string input by removing potentially dangerous characters
 */
const sanitizeString = (input) => {
  if (typeof input !== 'string') {
    return input;
  }
  
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
    .replace(/javascript:/gi, '') // Remove javascript protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .trim();
};

/**
 * Sanitize array of strings (like tags)
 */
const sanitizeArray = (arr) => {
  if (!Array.isArray(arr)) {
    return arr;
  }
  
  return arr.map(item => sanitizeString(item));
};

/**
 * Middleware to sanitize request body
 */
const sanitizeBody = (req, res, next) => {
  if (req.body) {
    // Sanitize title and content
    if (req.body.title) {
      req.body.title = sanitizeString(req.body.title);
    }
    
    if (req.body.content) {
      req.body.content = sanitizeHtml(req.body.content);
    }
    
    // Sanitize tags array
    if (req.body.tags) {
      req.body.tags = sanitizeArray(req.body.tags);
    }
  }
  
  next();
};

/**
 * Middleware to sanitize query parameters
 */
const sanitizeQuery = (req, res, next) => {
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (typeof req.query[key] === 'string') {
        req.query[key] = sanitizeString(req.query[key]);
      }
    });
  }
  
  next();
};

/**
 * Middleware to sanitize URL parameters
 */
const sanitizeParams = (req, res, next) => {
  if (req.params) {
    Object.keys(req.params).forEach(key => {
      if (typeof req.params[key] === 'string') {
        req.params[key] = sanitizeString(req.params[key]);
      }
    });
  }
  
  next();
};

module.exports = {
  sanitizeHtml,
  sanitizeString,
  sanitizeArray,
  sanitizeBody,
  sanitizeQuery,
  sanitizeParams
};
