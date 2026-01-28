/**
 * Authentication Routes
 * Handles user registration, login, and logout
 */
const express = require('express');
const router = express.Router();
const UserModel = require('../models/user');
const { generateToken, authenticate } = require('../middleware/auth');
const { asyncHandler, ApiError } = require('../middleware/errorHandler');
const InputValidator = require('../utils/validator');
const logger = require('../utils/logger');
const { csrfProtection, setCsrfToken } = require('../middleware/csrf');

// Apply CSRF token to all auth routes
router.use(setCsrfToken);

/**
 * POST /auth/register
 * Register a new user
 */
router.post('/register', csrfProtection, asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  // Validate required fields
  if (!username || !password) {
    throw ApiError.badRequest('Username and password are required');
  }

  // Create user
  const user = await UserModel.create(username, password);
  const token = generateToken(user.id);

  res.status(201).json({
    message: 'User registered successfully',
    user: {
      id: user.id,
      username: user.username
    },
    token
  });
}));

/**
 * POST /auth/login
 * Authenticate user and return token
 */
router.post('/login', csrfProtection, asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  // Validate required fields
  if (!username || !password) {
    throw ApiError.badRequest('Username and password are required');
  }

  // Authenticate user
  const user = await UserModel.authenticate(username, password);
  const token = generateToken(user.id);

  logger.securityEvent('user_login', { userId: user.id });

  res.json({
    message: 'Login successful',
    user: {
      id: user.id,
      username: user.username
    },
    token
  });
}));

/**
 * GET /auth/me
 * Get current user info
 */
router.get('/me', authenticate, asyncHandler(async (req, res) => {
  const user = UserModel.getById(req.userId);

  if (!user) {
    throw ApiError.notFound('User not found');
  }

  res.json({
    user: {
      id: user.id,
      username: user.username,
      createdAt: user.created_at,
      lastLogin: user.last_login
    }
  });
}));

/**
 * POST /auth/logout
 * Logout user (client should discard token)
 */
router.post('/logout', authenticate, asyncHandler(async (req, res) => {
  // In a production environment, you might want to:
  // 1. Add the token to a blacklist
  // 2. Store invalidated tokens in database
  // For stateless JWT, the client simply discards the token
  
  logger.securityEvent('user_logout', { userId: req.userId });

  res.json({
    message: 'Logged out successfully'
  });
}));

module.exports = router;
