const Joi = require('joi');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const logger = require('../utils/logger');

// Initialize DOMPurify with JSDOM for server-side use
const window = new JSDOM('').window;
const purify = DOMPurify(window);

/**
 * Joi validation schemas for different input types
 */
const schemas = {
  // User registration validation
  registration: Joi.object({
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'org', 'edu', 'gov'] } })
      .max(254)
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'string.max': 'Email address is too long',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .min(12)
      .max(128)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required()
      .messages({
        'string.min': 'Password must be at least 12 characters long',
        'string.max': 'Password is too long',
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        'any.required': 'Password is required'
      }),
    confirmPassword: Joi.string()
      .valid(Joi.ref('password'))
      .required()
      .messages({
        'any.only': 'Passwords do not match',
        'any.required': 'Password confirmation is required'
      })
  }),

  // User login validation
  login: Joi.object({
    email: Joi.string()
      .email()
      .max(254)
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .min(1)
      .max(128)
      .required()
      .messages({
        'any.required': 'Password is required'
      })
  }),

  // Note creation validation
  noteCreation: Joi.object({
    title: Joi.string()
      .min(1)
      .max(200)
      .required()
      .messages({
        'string.min': 'Title cannot be empty',
        'string.max': 'Title is too long (maximum 200 characters)',
        'any.required': 'Title is required'
      }),
    content: Joi.string()
      .max(10000)
      .allow('')
      .messages({
        'string.max': 'Content is too long (maximum 10,000 characters)'
      })
  }),

  // Note update validation
  noteUpdate: Joi.object({
    title: Joi.string()
      .min(1)
      .max(200)
      .optional()
      .messages({
        'string.min': 'Title cannot be empty',
        'string.max': 'Title is too long (maximum 200 characters)'
      }),
    content: Joi.string()
      .max(10000)
      .allow('')
      .optional()
      .messages({
        'string.max': 'Content is too long (maximum 10,000 characters)'
      })
  }),

  // Pagination validation
  pagination: Joi.object({
    page: Joi.number()
      .integer()
      .min(1)
      .max(1000)
      .default(1)
      .messages({
        'number.base': 'Page must be a number',
        'number.integer': 'Page must be an integer',
        'number.min': 'Page must be at least 1',
        'number.max': 'Page number is too large'
      }),
    limit: Joi.number()
      .integer()
      .min(1)
      .max(100)
      .default(10)
      .messages({
        'number.base': 'Limit must be a number',
        'number.integer': 'Limit must be an integer',
        'number.min': 'Limit must be at least 1',
        'number.max': 'Limit cannot exceed 100'
      })
  }),

  // File upload validation
  fileUpload: Joi.object({
    filename: Joi.string()
      .max(255)
      .pattern(/^[a-zA-Z0-9._-]+$/)
      .required()
      .messages({
        'string.max': 'Filename is too long',
        'string.pattern.base': 'Filename contains invalid characters',
        'any.required': 'Filename is required'
      }),
    mimetype: Joi.string()
      .valid('text/plain', 'text/markdown', 'application/json')
      .required()
      .messages({
        'any.only': 'File type not allowed',
        'any.required': 'File type is required'
      }),
    size: Joi.number()
      .max(1024 * 1024) // 1MB limit
      .required()
      .messages({
        'number.max': 'File size exceeds 1MB limit',
        'any.required': 'File size is required'
      })
  })
};

/**
 * HTML sanitization function to prevent XSS attacks
 * @param {string} input - The input string to sanitize
 * @returns {string} - Sanitized string
 */
function sanitizeHtml(input) {
  if (typeof input !== 'string') {
    return input;
  }

  // Configure DOMPurify with strict settings to remove all HTML
  const config = {
    ALLOWED_TAGS: [], // No HTML tags allowed
    ALLOWED_ATTR: [], // No attributes allowed
    KEEP_CONTENT: true, // Keep text content
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    RETURN_DOM_IMPORT: false
  };

  // First pass: Remove HTML tags and attributes
  let sanitized = purify.sanitize(input, config);

  // Second pass: Remove dangerous protocols and patterns
  sanitized = sanitized
    .replace(/javascript:/gi, '')
    .replace(/vbscript:/gi, '')
    .replace(/data:/gi, '')
    .replace(/about:/gi, '');

  // Third pass: Remove common SQL injection patterns (be more selective)
  sanitized = sanitized
    .replace(/;\s*(DROP|DELETE|INSERT|UPDATE|SELECT|UNION|CREATE|ALTER|EXEC|EXECUTE)/gi, '')
    .replace(/(DROP|DELETE|INSERT|UPDATE|SELECT|UNION|CREATE|ALTER|EXEC|EXECUTE)\s+(TABLE|FROM|INTO|WHERE)/gi, '')
    .replace(/'\s*(OR|AND)\s*'1'\s*=\s*'1/gi, '')
    .replace(/--[^\r\n]*/g, '') // Remove SQL comments
    .replace(/\/\*[\s\S]*?\*\//g, ''); // Remove block comments

  return sanitized;
}

/**
 * Recursively sanitize all string values in an object
 * @param {any} obj - The object to sanitize
 * @returns {any} - Sanitized object
 */
function sanitizeObject(obj) {
  if (typeof obj === 'string') {
    return sanitizeHtml(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }
  
  if (obj && typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = sanitizeObject(value);
    }
    return sanitized;
  }
  
  return obj;
}

/**
 * Generic validation middleware factory
 * @param {Joi.Schema} schema - Joi schema to validate against
 * @param {string} source - Source of data to validate ('body', 'query', 'params')
 * @returns {Function} - Express middleware function
 */
function validateInput(schema, source = 'body') {
  return (req, res, next) => {
    const data = req[source];
    
    // Validate the data against the schema
    const { error, value } = schema.validate(data, {
      abortEarly: false, // Return all validation errors
      stripUnknown: true, // Remove unknown properties
      convert: true // Convert types when possible
    });

    if (error) {
      const validationErrors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      logger.warn('Validation failed', {
        source,
        errors: validationErrors,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Input validation failed',
          details: validationErrors,
          timestamp: new Date().toISOString()
        }
      });
    }

    // Sanitize the validated data
    req[source] = sanitizeObject(value);
    next();
  };
}

/**
 * Request size limiting middleware
 * @param {number} maxSize - Maximum request size in bytes
 * @returns {Function} - Express middleware function
 */
function limitRequestSize(maxSize = 1024 * 1024) { // Default 1MB
  return (req, res, next) => {
    const contentLength = parseInt(req.get('Content-Length') || '0', 10);
    
    if (contentLength > maxSize) {
      logger.warn('Request size limit exceeded', {
        contentLength,
        maxSize,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.status(413).json({
        error: {
          code: 'REQUEST_TOO_LARGE',
          message: 'Request size exceeds limit',
          maxSize,
          timestamp: new Date().toISOString()
        }
      });
    }

    next();
  };
}

/**
 * File upload validation middleware
 * @param {Object} options - Validation options
 * @returns {Function} - Express middleware function
 */
function validateFileUpload(options = {}) {
  const {
    maxSize = 1024 * 1024, // 1MB default
    allowedTypes = ['text/plain', 'text/markdown', 'application/json'],
    maxFiles = 1
  } = options;

  return (req, res, next) => {
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({
        error: {
          code: 'NO_FILE_UPLOADED',
          message: 'No file was uploaded',
          timestamp: new Date().toISOString()
        }
      });
    }

    const files = Array.isArray(req.files.file) ? req.files.file : [req.files.file];
    
    if (files.length > maxFiles) {
      return res.status(400).json({
        error: {
          code: 'TOO_MANY_FILES',
          message: `Maximum ${maxFiles} file(s) allowed`,
          timestamp: new Date().toISOString()
        }
      });
    }

    for (const file of files) {
      // Validate file size
      if (file.size > maxSize) {
        return res.status(400).json({
          error: {
            code: 'FILE_TOO_LARGE',
            message: `File size exceeds ${maxSize} bytes`,
            filename: file.name,
            timestamp: new Date().toISOString()
          }
        });
      }

      // Validate file type
      if (!allowedTypes.includes(file.mimetype)) {
        return res.status(400).json({
          error: {
            code: 'INVALID_FILE_TYPE',
            message: 'File type not allowed',
            allowedTypes,
            receivedType: file.mimetype,
            timestamp: new Date().toISOString()
          }
        });
      }

      // Basic content scanning for malicious patterns
      const suspiciousPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /onload\s*=/gi,
        /onerror\s*=/gi,
        /onclick\s*=/gi
      ];

      const fileContent = file.data.toString();
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(fileContent)) {
          logger.warn('Malicious content detected in file upload', {
            filename: file.name,
            pattern: pattern.toString(),
            ip: req.ip,
            userAgent: req.get('User-Agent')
          });

          return res.status(400).json({
            error: {
              code: 'MALICIOUS_CONTENT_DETECTED',
              message: 'File contains potentially malicious content',
              timestamp: new Date().toISOString()
            }
          });
        }
      }
    }

    next();
  };
}

// Export validation middleware functions
module.exports = {
  schemas,
  validateInput,
  sanitizeHtml,
  sanitizeObject,
  limitRequestSize,
  validateFileUpload,
  
  // Specific validation middleware for common use cases
  validateRegistration: validateInput(schemas.registration, 'body'),
  validateLogin: validateInput(schemas.login, 'body'),
  validateNoteCreation: validateInput(schemas.noteCreation, 'body'),
  validateNoteUpdate: validateInput(schemas.noteUpdate, 'body'),
  validatePagination: validateInput(schemas.pagination, 'query'),
  validateFileUploadDefault: validateFileUpload()
};