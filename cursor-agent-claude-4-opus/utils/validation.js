const Joi = require('joi');

// Custom password validation
const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;

// User validation schemas
const userSchemas = {
  register: Joi.object({
    username: Joi.string()
      .alphanum()
      .min(3)
      .max(30)
      .required()
      .messages({
        'string.alphanum': 'Username must only contain alphanumeric characters',
        'string.min': 'Username must be at least 3 characters long',
        'string.max': 'Username must not exceed 30 characters',
        'any.required': 'Username is required'
      }),
    
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .max(255)
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'string.max': 'Email must not exceed 255 characters',
        'any.required': 'Email is required'
      }),
    
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(passwordPattern)
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.max': 'Password must not exceed 128 characters',
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        'any.required': 'Password is required'
      })
  }),

  login: Joi.object({
    username: Joi.string()
      .required()
      .messages({
        'any.required': 'Username is required'
      }),
    
    password: Joi.string()
      .required()
      .messages({
        'any.required': 'Password is required'
      })
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string()
      .required()
      .messages({
        'any.required': 'Refresh token is required'
      })
  })
};

// Note validation schemas
const noteSchemas = {
  create: Joi.object({
    title: Joi.string()
      .min(1)
      .max(255)
      .required()
      .messages({
        'string.min': 'Title cannot be empty',
        'string.max': 'Title must not exceed 255 characters',
        'any.required': 'Title is required'
      }),
    
    content: Joi.string()
      .min(1)
      .max(10000)
      .required()
      .messages({
        'string.min': 'Content cannot be empty',
        'string.max': 'Content must not exceed 10000 characters',
        'any.required': 'Content is required'
      })
  }),

  update: Joi.object({
    title: Joi.string()
      .min(1)
      .max(255)
      .optional()
      .messages({
        'string.min': 'Title cannot be empty',
        'string.max': 'Title must not exceed 255 characters'
      }),
    
    content: Joi.string()
      .min(1)
      .max(10000)
      .optional()
      .messages({
        'string.min': 'Content cannot be empty',
        'string.max': 'Content must not exceed 10000 characters'
      })
  }).or('title', 'content'),

  id: Joi.object({
    id: Joi.number()
      .integer()
      .positive()
      .required()
      .messages({
        'number.base': 'ID must be a number',
        'number.integer': 'ID must be an integer',
        'number.positive': 'ID must be positive',
        'any.required': 'ID is required'
      })
  }),

  pagination: Joi.object({
    page: Joi.number()
      .integer()
      .min(1)
      .default(1)
      .messages({
        'number.base': 'Page must be a number',
        'number.integer': 'Page must be an integer',
        'number.min': 'Page must be at least 1'
      }),
    
    limit: Joi.number()
      .integer()
      .min(1)
      .max(100)
      .default(20)
      .messages({
        'number.base': 'Limit must be a number',
        'number.integer': 'Limit must be an integer',
        'number.min': 'Limit must be at least 1',
        'number.max': 'Limit must not exceed 100'
      })
  })
};

// Validation middleware factory
function validate(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
      convert: true
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));

      return res.status(400).json({
        error: 'Validation failed',
        details: errors
      });
    }

    req.validatedBody = value;
    next();
  };
}

// Validate query parameters
function validateQuery(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.query, {
      abortEarly: false,
      stripUnknown: true,
      convert: true
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));

      return res.status(400).json({
        error: 'Invalid query parameters',
        details: errors
      });
    }

    req.validatedQuery = value;
    next();
  };
}

// Validate route parameters
function validateParams(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.params, {
      abortEarly: false,
      stripUnknown: true,
      convert: true
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));

      return res.status(400).json({
        error: 'Invalid route parameters',
        details: errors
      });
    }

    req.validatedParams = value;
    next();
  };
}

module.exports = {
  userSchemas,
  noteSchemas,
  validate,
  validateQuery,
  validateParams
};