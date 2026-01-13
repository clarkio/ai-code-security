const { body, param, query, validationResult } = require('express-validator');

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map(e => ({
        field: e.path,
        message: e.msg
      }))
    });
  }
  next();
};

const usernameValidator = body('username')
  .trim()
  .isLength({ min: 3, max: 30 })
  .withMessage('Username must be 3-30 characters')
  .matches(/^[a-zA-Z0-9_]+$/)
  .withMessage('Username can only contain letters, numbers, and underscores');

const emailValidator = body('email')
  .trim()
  .isEmail()
  .withMessage('Invalid email address')
  .normalizeEmail();

const passwordValidator = body('password')
  .trim()
  .isLength({ min: 12 })
  .withMessage('Password must be at least 12 characters')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  .withMessage('Password must contain uppercase, lowercase, number, and special character');

const titleValidator = body('title')
  .trim()
  .isLength({ min: 1, max: 200 })
  .withMessage('Title must be 1-200 characters')
  .escape();

const contentValidator = body('content')
  .optional()
  .trim()
  .isLength({ max: 10000 })
  .withMessage('Content must be less than 10000 characters');

const idValidator = param('id')
  .isUUID()
  .withMessage('Invalid ID format');

const paginationValidator = query('page')
  .optional()
  .isInt({ min: 1, max: 1000 })
  .toInt();

const limitValidator = query('limit')
  .optional()
  .isInt({ min: 1, max: 100 })
  .toInt();

module.exports = {
  validate,
  usernameValidator,
  emailValidator,
  passwordValidator,
  titleValidator,
  contentValidator,
  idValidator,
  paginationValidator,
  limitValidator
};
