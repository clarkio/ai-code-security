const { body, param, query, validationResult } = require('express-validator');

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const formattedErrors = errors.array().map(error => ({
      field: error.path,
      message: error.msg,
      value: error.value
    }));
    
    return res.status(400).json({
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      errors: formattedErrors
    });
  }
  
  next();
};

// User validation rules
const userValidation = {
  register: [
    body('username')
      .trim()
      .isLength({ min: 3, max: 50 }).withMessage('Username must be between 3 and 50 characters')
      .isAlphanumeric().withMessage('Username must contain only letters and numbers')
      .notEmpty().withMessage('Username is required'),
    
    body('email')
      .trim()
      .isEmail().withMessage('Invalid email address')
      .normalizeEmail()
      .isLength({ max: 255 }).withMessage('Email must not exceed 255 characters')
      .notEmpty().withMessage('Email is required'),
    
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
      .notEmpty().withMessage('Password is required'),
    
    body('confirmPassword')
      .custom((value, { req }) => value === req.body.password)
      .withMessage('Passwords do not match'),
    
    handleValidationErrors
  ],
  
  login: [
    body('username')
      .trim()
      .notEmpty().withMessage('Username is required'),
    
    body('password')
      .notEmpty().withMessage('Password is required'),
    
    handleValidationErrors
  ],
  
  updateProfile: [
    body('email')
      .optional()
      .trim()
      .isEmail().withMessage('Invalid email address')
      .normalizeEmail()
      .isLength({ max: 255 }).withMessage('Email must not exceed 255 characters'),
    
    body('currentPassword')
      .if(body('newPassword').exists())
      .notEmpty().withMessage('Current password is required to change password'),
    
    body('newPassword')
      .optional()
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    
    body('confirmNewPassword')
      .if(body('newPassword').exists())
      .custom((value, { req }) => value === req.body.newPassword)
      .withMessage('Passwords do not match'),
    
    handleValidationErrors
  ]
};

// Note validation rules
const noteValidation = {
  create: [
    body('title')
      .trim()
      .isLength({ min: 1, max: 255 }).withMessage('Title must be between 1 and 255 characters')
      .notEmpty().withMessage('Title is required')
      .escape(), // Escape HTML entities
    
    body('content')
      .trim()
      .isLength({ min: 1, max: 50000 }).withMessage('Content must be between 1 and 50000 characters')
      .notEmpty().withMessage('Content is required'),
    
    body('is_public')
      .optional()
      .isBoolean().withMessage('is_public must be a boolean'),
    
    body('tags')
      .optional()
      .isArray({ max: 10 }).withMessage('Maximum 10 tags allowed')
      .custom((tags) => {
        return tags.every(tag => 
          typeof tag === 'string' && 
          tag.length <= 50 && 
          /^[\w\s-]+$/.test(tag)
        );
      }).withMessage('Each tag must be a string with max 50 characters and contain only letters, numbers, spaces, and hyphens'),
    
    handleValidationErrors
  ],
  
  update: [
    body('title')
      .optional()
      .trim()
      .isLength({ min: 1, max: 255 }).withMessage('Title must be between 1 and 255 characters')
      .escape(),
    
    body('content')
      .optional()
      .trim()
      .isLength({ min: 1, max: 50000 }).withMessage('Content must be between 1 and 50000 characters'),
    
    body('is_public')
      .optional()
      .isBoolean().withMessage('is_public must be a boolean'),
    
    body('tags')
      .optional()
      .isArray({ max: 10 }).withMessage('Maximum 10 tags allowed')
      .custom((tags) => {
        return tags.every(tag => 
          typeof tag === 'string' && 
          tag.length <= 50 && 
          /^[\w\s-]+$/.test(tag)
        );
      }).withMessage('Each tag must be a string with max 50 characters and contain only letters, numbers, spaces, and hyphens'),
    
    handleValidationErrors
  ],
  
  getById: [
    param('id')
      .isUUID().withMessage('Invalid note ID format'),
    
    handleValidationErrors
  ],
  
  list: [
    query('page')
      .optional()
      .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    
    query('search')
      .optional()
      .trim()
      .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
      .escape(),
    
    query('tag')
      .optional()
      .trim()
      .isLength({ max: 50 }).withMessage('Tag must not exceed 50 characters')
      .matches(/^[\w\s-]+$/).withMessage('Tag must contain only letters, numbers, spaces, and hyphens'),
    
    handleValidationErrors
  ]
};

// Common validation rules
const commonValidation = {
  uuidParam: [
    param('id')
      .isUUID().withMessage('Invalid ID format'),
    
    handleValidationErrors
  ],
  
  pagination: [
    query('page')
      .optional()
      .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    
    handleValidationErrors
  ]
};

module.exports = {
  userValidation,
  noteValidation,
  commonValidation,
  handleValidationErrors
};