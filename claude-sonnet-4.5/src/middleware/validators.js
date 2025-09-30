const { body, param, validationResult } = require("express-validator");

/**
 * Validation middleware
 */
exports.validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array().map((err) => ({
        field: err.path,
        message: err.msg,
      })),
    });
  }
  next();
};

/**
 * User registration validation
 */
exports.registerValidation = [
  body("username")
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be between 3 and 30 characters")
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage(
      "Username can only contain letters, numbers, underscores, and hyphens"
    )
    .escape(),

  body("password")
    .isLength({ min: 8, max: 128 })
    .withMessage("Password must be between 8 and 128 characters")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage(
      "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    ),

  body("confirmPassword")
    .custom((value, { req }) => value === req.body.password)
    .withMessage("Passwords do not match"),
];

/**
 * User login validation
 */
exports.loginValidation = [
  body("username")
    .trim()
    .notEmpty()
    .withMessage("Username is required")
    .escape(),

  body("password").notEmpty().withMessage("Password is required"),
];

/**
 * Note creation/update validation
 */
exports.noteValidation = [
  body("title")
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage("Title must be between 1 and 200 characters")
    .escape(),

  body("content")
    .trim()
    .isLength({ min: 1, max: 10000 })
    .withMessage("Content must be between 1 and 10000 characters")
    .escape(),
];

/**
 * ID parameter validation
 */
exports.idValidation = [
  param("id")
    .trim()
    .matches(
      /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
    )
    .withMessage("Invalid ID format"),
];
