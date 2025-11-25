/**
 * Input Validation Schemas
 * Comprehensive validation using express-validator
 */

const { body, param, query } = require("express-validator");

// Password requirements (OWASP guidelines)
const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_MAX_LENGTH = 128;

/**
 * User registration validation
 */
const registerValidation = [
  body("username")
    .trim()
    .notEmpty()
    .withMessage("Username is required")
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be 3-30 characters")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username can only contain letters, numbers, and underscores")
    .escape(),

  body("email")
    .trim()
    .notEmpty()
    .withMessage("Email is required")
    .isEmail()
    .withMessage("Invalid email format")
    .normalizeEmail()
    .isLength({ max: 254 })
    .withMessage("Email is too long"),

  body("password")
    .notEmpty()
    .withMessage("Password is required")
    .isLength({ min: PASSWORD_MIN_LENGTH, max: PASSWORD_MAX_LENGTH })
    .withMessage(
      `Password must be ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} characters`
    )
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain at least one number")
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage("Password must contain at least one special character")
    .custom((value, { req }) => {
      // Check for common weak passwords
      const weakPasswords = ["password123", "qwerty123", "12345678"];
      if (weakPasswords.some((weak) => value.toLowerCase().includes(weak))) {
        throw new Error("Password is too common");
      }
      // Don't allow username in password
      if (
        req.body.username &&
        value.toLowerCase().includes(req.body.username.toLowerCase())
      ) {
        throw new Error("Password cannot contain your username");
      }
      return true;
    }),

  body("confirmPassword")
    .notEmpty()
    .withMessage("Password confirmation is required")
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not match");
      }
      return true;
    }),
];

/**
 * Login validation
 */
const loginValidation = [
  body("username")
    .trim()
    .notEmpty()
    .withMessage("Username is required")
    .isLength({ max: 30 })
    .withMessage("Username is too long")
    .escape(),

  body("password")
    .notEmpty()
    .withMessage("Password is required")
    .isLength({ max: PASSWORD_MAX_LENGTH })
    .withMessage("Password is too long"),
];

/**
 * Change password validation
 */
const changePasswordValidation = [
  body("currentPassword")
    .notEmpty()
    .withMessage("Current password is required"),

  body("newPassword")
    .notEmpty()
    .withMessage("New password is required")
    .isLength({ min: PASSWORD_MIN_LENGTH, max: PASSWORD_MAX_LENGTH })
    .withMessage(
      `Password must be ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} characters`
    )
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain at least one number")
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage("Password must contain at least one special character")
    .custom((value, { req }) => {
      if (value === req.body.currentPassword) {
        throw new Error("New password must be different from current password");
      }
      return true;
    }),

  body("confirmNewPassword")
    .notEmpty()
    .withMessage("Password confirmation is required")
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error("Passwords do not match");
      }
      return true;
    }),
];

/**
 * Note creation validation
 */
const createNoteValidation = [
  body("title")
    .trim()
    .notEmpty()
    .withMessage("Title is required")
    .isLength({ min: 1, max: 200 })
    .withMessage("Title must be 1-200 characters"),

  body("content")
    .trim()
    .notEmpty()
    .withMessage("Content is required")
    .isLength({ min: 1, max: 50000 })
    .withMessage("Content must be 1-50000 characters"),
];

/**
 * Note update validation
 */
const updateNoteValidation = [
  param("id")
    .notEmpty()
    .withMessage("Note ID is required")
    .isUUID(4)
    .withMessage("Invalid note ID format"),

  body("title")
    .optional()
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage("Title must be 1-200 characters"),

  body("content")
    .optional()
    .trim()
    .isLength({ min: 1, max: 50000 })
    .withMessage("Content must be 1-50000 characters"),
];

/**
 * Note ID parameter validation
 */
const noteIdValidation = [
  param("id")
    .notEmpty()
    .withMessage("Note ID is required")
    .isUUID(4)
    .withMessage("Invalid note ID format"),
];

/**
 * Pagination validation
 */
const paginationValidation = [
  query("limit")
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage("Limit must be 1-100")
    .toInt(),

  query("offset")
    .optional()
    .isInt({ min: 0 })
    .withMessage("Offset must be a positive number")
    .toInt(),

  query("sortBy")
    .optional()
    .isIn(["created_at", "updated_at", "title"])
    .withMessage("Invalid sort field"),

  query("sortOrder")
    .optional()
    .isIn(["ASC", "DESC", "asc", "desc"])
    .withMessage("Invalid sort order"),
];

/**
 * Search validation
 */
const searchValidation = [
  query("q")
    .trim()
    .notEmpty()
    .withMessage("Search query is required")
    .isLength({ min: 1, max: 100 })
    .withMessage("Search query must be 1-100 characters")
    .escape(),

  ...paginationValidation,
];

/**
 * Refresh token validation
 */
const refreshTokenValidation = [
  body("refreshToken")
    .notEmpty()
    .withMessage("Refresh token is required")
    .isLength({ min: 128, max: 128 })
    .withMessage("Invalid refresh token format")
    .matches(/^[a-f0-9]+$/)
    .withMessage("Invalid refresh token format"),
];

module.exports = {
  registerValidation,
  loginValidation,
  changePasswordValidation,
  createNoteValidation,
  updateNoteValidation,
  noteIdValidation,
  paginationValidation,
  searchValidation,
  refreshTokenValidation,
};
