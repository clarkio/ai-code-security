const Joi = require('joi');
const { body, param, validationResult } = require('express-validator');

// Note validation schemas
const noteSchema = Joi.object({
  title: Joi.string()
    .min(1)
    .max(200)
    .required()
    .pattern(/^[^<>]*$/) // Prevent HTML tags
    .messages({
      'string.empty': 'Title is required',
      'string.min': 'Title must be at least 1 character long',
      'string.max': 'Title must not exceed 200 characters',
      'string.pattern.base': 'Title contains invalid characters',
      'any.required': 'Title is required'
    }),
  
  content: Joi.string()
    .min(1)
    .max(10000)
    .required()
    .messages({
      'string.empty': 'Content is required',
      'string.min': 'Content must be at least 1 character long',
      'string.max': 'Content must not exceed 10,000 characters',
      'any.required': 'Content is required'
    }),
  
  tags: Joi.array()
    .items(
      Joi.string()
        .min(1)
        .max(50)
        .pattern(/^[a-zA-Z0-9\s-_]*$/) // Alphanumeric with spaces, hyphens, underscores
    )
    .max(10)
    .optional()
    .messages({
      'array.base': 'Tags must be an array',
      'array.max': 'Maximum 10 tags allowed',
      'string.pattern.base': 'Tags can only contain letters, numbers, spaces, hyphens, and underscores'
    })
});

const noteUpdateSchema = Joi.object({
  title: Joi.string()
    .min(1)
    .max(200)
    .optional()
    .pattern(/^[^<>]*$/)
    .messages({
      'string.min': 'Title must be at least 1 character long',
      'string.max': 'Title must not exceed 200 characters',
      'string.pattern.base': 'Title contains invalid characters'
    }),
  
  content: Joi.string()
    .min(1)
    .max(10000)
    .optional()
    .messages({
      'string.min': 'Content must be at least 1 character long',
      'string.max': 'Content must not exceed 10,000 characters'
    }),
  
  tags: Joi.array()
    .items(
      Joi.string()
        .min(1)
        .max(50)
        .pattern(/^[a-zA-Z0-9\s-_]*$/)
    )
    .max(10)
    .optional()
    .messages({
      'array.base': 'Tags must be an array',
      'array.max': 'Maximum 10 tags allowed',
      'string.pattern.base': 'Tags can only contain letters, numbers, spaces, hyphens, and underscores'
    })
}).min(1).messages({
  'object.min': 'At least one field must be provided for update'
});

// Express-validator middleware
const validateNote = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ max: 200 })
    .withMessage('Title must not exceed 200 characters')
    .custom(value => {
      if (/<[^>]*>/.test(value)) {
        throw new Error('Title cannot contain HTML tags');
      }
      return true;
    }),
  
  body('content')
    .trim()
    .notEmpty()
    .withMessage('Content is required')
    .isLength({ max: 10000 })
    .withMessage('Content must not exceed 10,000 characters'),
  
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array')
    .custom(tags => {
      if (tags.length > 10) {
        throw new Error('Maximum 10 tags allowed');
      }
      for (const tag of tags) {
        if (typeof tag !== 'string' || tag.length > 50) {
          throw new Error('Each tag must be a string with max 50 characters');
        }
        if (!/^[a-zA-Z0-9\s-_]*$/.test(tag)) {
          throw new Error('Tags can only contain letters, numbers, spaces, hyphens, and underscores');
        }
      }
      return true;
    }),
  
  // Handle validation errors
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation Error',
        details: errors.array()
      });
    }
    next();
  }
];

const validateNoteUpdate = [
  body('title')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Title cannot be empty')
    .isLength({ max: 200 })
    .withMessage('Title must not exceed 200 characters')
    .custom(value => {
      if (/<[^>]*>/.test(value)) {
        throw new Error('Title cannot contain HTML tags');
      }
      return true;
    }),
  
  body('content')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Content cannot be empty')
    .isLength({ max: 10000 })
    .withMessage('Content must not exceed 10,000 characters'),
  
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array')
    .custom(tags => {
      if (tags.length > 10) {
        throw new Error('Maximum 10 tags allowed');
      }
      for (const tag of tags) {
        if (typeof tag !== 'string' || tag.length > 50) {
          throw new Error('Each tag must be a string with max 50 characters');
        }
        if (!/^[a-zA-Z0-9\s-_]*$/.test(tag)) {
          throw new Error('Tags can only contain letters, numbers, spaces, hyphens, and underscores');
        }
      }
      return true;
    }),
  
  // Check if at least one field is provided
  (req, res, next) => {
    if (!req.body.title && !req.body.content && !req.body.tags) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'At least one field must be provided for update'
      });
    }
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation Error',
        details: errors.array()
      });
    }
    next();
  }
];

const validateNoteId = [
  param('id')
    .isUUID()
    .withMessage('Invalid note ID format'),
  
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation Error',
        details: errors.array()
      });
    }
    next();
  }
];

// Joi validation functions
const validateNoteWithJoi = (data) => {
  return noteSchema.validate(data, { abortEarly: false });
};

const validateNoteUpdateWithJoi = (data) => {
  return noteUpdateSchema.validate(data, { abortEarly: false });
};

module.exports = {
  validateNote,
  validateNoteUpdate,
  validateNoteId,
  validateNoteWithJoi,
  validateNoteUpdateWithJoi,
  noteSchema,
  noteUpdateSchema
};
