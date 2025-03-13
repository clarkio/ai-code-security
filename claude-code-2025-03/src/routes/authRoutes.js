const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { isAuthenticated, isNotAuthenticated } = require('../middleware/auth');
const { 
  loginValidationRules, 
  registerValidationRules, 
  validate 
} = require('../middleware/validation');
const { authLimiter } = require('../middleware/security');

// Register new user (rate limited)
router.post(
  '/register',
  authLimiter,
  isNotAuthenticated,
  registerValidationRules,
  validate,
  authController.register
);

// Login user (rate limited)
router.post(
  '/login',
  authLimiter,
  isNotAuthenticated,
  loginValidationRules,
  validate,
  authController.login
);

// Logout user (must be authenticated)
router.post(
  '/logout',
  isAuthenticated,
  authController.logout
);

// Get current user info (must be authenticated)
router.get(
  '/me',
  isAuthenticated,
  authController.getCurrentUser
);

module.exports = router;