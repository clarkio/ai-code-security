"use strict";

/**
 * Validation schemas using express-validator.
 * Every user input is validated & sanitized before reaching the DB.
 */

const { body, validationResult } = require("express-validator");
const { sanitizePlainText, clampLength } = require("../utils/sanitize");

// Username: 3-32 chars, alphanumeric + underscore only
const usernameRules = [
  body("username")
    .trim()
    .isLength({ min: 3, max: 32 })
    .withMessage("Username must be 3-32 characters")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username may only contain letters, numbers, and underscores")
    .customSanitizer((v) => sanitizePlainText(v)),
];

// Password: min 12 chars, must include upper, lower, number, special
const passwordRules = [
  body("password")
    .isLength({ min: 12, max: 128 })
    .withMessage("Password must be 12-128 characters")
    .matches(/[A-Z]/)
    .withMessage("Password must contain an uppercase letter")
    .matches(/[a-z]/)
    .withMessage("Password must contain a lowercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain a number")
    .matches(/[^A-Za-z0-9]/)
    .withMessage("Password must contain a special character"),
];

const registerRules = [...usernameRules, ...passwordRules];
const loginRules = [...usernameRules, body("password").isLength({ min: 1 })];

// Note title: 1-200 chars
const noteTitleRules = [
  body("title")
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage("Title is required (max 200 chars)")
    .customSanitizer((v) => clampLength(sanitizePlainText(v), 200)),
];

// Note body: 1-10000 chars
const noteBodyRules = [
  body("body")
    .isLength({ min: 1, max: 10000 })
    .withMessage("Body is required (max 10000 chars)")
    .customSanitizer((v) => clampLength(sanitizePlainText(v), 10000)),
];

const noteRules = [...noteTitleRules, ...noteBodyRules];

// Middleware to collect validation errors into a uniform 422 response
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: "Validation failed",
      details: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }
  next();
}

module.exports = {
  registerRules,
  loginRules,
  noteRules,
  handleValidationErrors,
};
