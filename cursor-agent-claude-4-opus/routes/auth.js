const express = require('express');
const router = express.Router();
const { userStatements, auditStatements } = require('../db/database');
const { validate, userSchemas } = require('../utils/validation');
const { 
  hashPassword, 
  verifyPassword, 
  generateAccessToken, 
  generateRefreshToken,
  saveRefreshToken,
  verifyRefreshToken,
  revokeRefreshToken,
  revokeAllUserTokens
} = require('../utils/auth');
const { AppError, asyncHandler } = require('../middleware/errorHandler');
const { authenticate } = require('../middleware/authenticate');
const logger = require('../utils/logger');
const xss = require('xss');

// Register new user
router.post('/register', validate(userSchemas.register), asyncHandler(async (req, res) => {
  const { username, email, password } = req.validatedBody;
  
  // Sanitize input
  const sanitizedUsername = xss(username);
  const sanitizedEmail = xss(email);
  
  // Check if user already exists
  const existingUser = await userStatements.findByUsername({ username: sanitizedUsername });
  if (existingUser) {
    throw new AppError('Username already exists', 409);
  }
  
  const existingEmail = await userStatements.findByEmail({ email: sanitizedEmail });
  if (existingEmail) {
    throw new AppError('Email already registered', 409);
  }
  
  // Hash password
  const passwordHash = await hashPassword(password);
  
  // Create user
  try {
    const result = await userStatements.create({
      username: sanitizedUsername,
      email: sanitizedEmail,
      password_hash: passwordHash
    });
    
    const userId = result.lastID;
    
    // Log registration
    await auditStatements.create({
      user_id: userId,
      action: 'REGISTER',
      resource_type: 'USER',
      resource_id: userId,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    // Generate tokens
    const accessToken = generateAccessToken(userId);
    const refreshToken = generateRefreshToken();
    
    // Save refresh token
    await saveRefreshToken(userId, refreshToken);
    
    res.status(201).json({
      message: 'User registered successfully',
      accessToken,
      refreshToken,
      user: {
        id: userId,
        username: sanitizedUsername,
        email: sanitizedEmail
      }
    });
  } catch (error) {
    logger.error('Registration error:', error);
    throw new AppError('Registration failed', 500);
  }
}));

// Login
router.post('/login', validate(userSchemas.login), asyncHandler(async (req, res) => {
  const { username, password } = req.validatedBody;
  
  // Sanitize input
  const sanitizedUsername = xss(username);
  
  // Find user
  const user = await userStatements.findByUsername({ username: sanitizedUsername });
  
  if (!user) {
    // Log failed attempt
    await auditStatements.create({
      user_id: null,
      action: 'LOGIN_FAILED',
      resource_type: 'AUTH',
      resource_id: null,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    throw new AppError('Invalid credentials', 401);
  }
  
  // Check if account is locked
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    throw new AppError('Account is locked. Please try again later.', 403);
  }
  
  // Verify password
  const isValidPassword = await verifyPassword(password, user.password_hash);
  
  if (!isValidPassword) {
    // Update failed login attempts
    const attempts = user.failed_login_attempts + 1;
    const maxAttempts = 5;
    
    await userStatements.updateLoginAttempts({
      id: user.id,
      attempts,
      timestamp: new Date().toISOString()
    });
    
    // Lock account after max attempts
    if (attempts >= maxAttempts) {
      const lockDuration = 30 * 60 * 1000; // 30 minutes
      const lockedUntil = new Date(Date.now() + lockDuration).toISOString();
      
      await userStatements.lockAccount({
        id: user.id,
        locked_until: lockedUntil
      });
      
      logger.warn(`Account locked for user ${user.username} after ${maxAttempts} failed attempts`);
    }
    
    // Log failed attempt
    await auditStatements.create({
      user_id: user.id,
      action: 'LOGIN_FAILED',
      resource_type: 'AUTH',
      resource_id: null,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    throw new AppError('Invalid credentials', 401);
  }
  
  // Reset failed login attempts
  await userStatements.resetLoginAttempts({ id: user.id });
  
  // Generate tokens
  const accessToken = generateAccessToken(user.id);
  const refreshToken = generateRefreshToken();
  
  // Save refresh token
  await saveRefreshToken(user.id, refreshToken);
  
  // Log successful login
  await auditStatements.create({
    user_id: user.id,
    action: 'LOGIN',
    resource_type: 'AUTH',
    resource_id: null,
    ip_address: req.ip,
    user_agent: req.get('user-agent')
  });
  
  res.json({
    message: 'Login successful',
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      username: user.username,
      email: user.email
    }
  });
}));

// Refresh token
router.post('/refresh', validate(userSchemas.refreshToken), asyncHandler(async (req, res) => {
  const { refreshToken } = req.validatedBody;
  
  // Verify refresh token
  const tokenResult = await verifyRefreshToken(refreshToken);
  
  if (!tokenResult.valid) {
    throw new AppError(tokenResult.reason || 'Invalid refresh token', 401);
  }
  
  // Get user
  const user = await userStatements.findById({ id: tokenResult.userId });
  
  if (!user) {
    throw new AppError('User not found', 401);
  }
  
  // Revoke old refresh token
  await revokeRefreshToken(refreshToken);
  
  // Generate new tokens
  const newAccessToken = generateAccessToken(user.id);
  const newRefreshToken = generateRefreshToken();
  
  // Save new refresh token
  await saveRefreshToken(user.id, newRefreshToken);
  
  // Log token refresh
  await auditStatements.create({
    user_id: user.id,
    action: 'TOKEN_REFRESH',
    resource_type: 'AUTH',
    resource_id: null,
    ip_address: req.ip,
    user_agent: req.get('user-agent')
  });
  
  res.json({
    accessToken: newAccessToken,
    refreshToken: newRefreshToken
  });
}));

// Logout
router.post('/logout', authenticate, asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;
  
  if (refreshToken) {
    // Revoke the specific refresh token
    await revokeRefreshToken(refreshToken);
  }
  
  // Log logout
  await auditStatements.create({
    user_id: req.user.id,
    action: 'LOGOUT',
    resource_type: 'AUTH',
    resource_id: null,
    ip_address: req.ip,
    user_agent: req.get('user-agent')
  });
  
  res.json({ message: 'Logged out successfully' });
}));

// Logout from all devices
router.post('/logout-all', authenticate, asyncHandler(async (req, res) => {
  // Revoke all refresh tokens for the user
  const revokedCount = await revokeAllUserTokens(req.user.id);
  
  // Log logout from all devices
  await auditStatements.create({
    user_id: req.user.id,
    action: 'LOGOUT_ALL',
    resource_type: 'AUTH',
    resource_id: null,
    ip_address: req.ip,
    user_agent: req.get('user-agent')
  });
  
  res.json({ 
    message: 'Logged out from all devices successfully',
    revokedTokens: revokedCount
  });
}));

// Get current user
router.get('/me', authenticate, (req, res) => {
  res.json({
    user: req.user
  });
});

module.exports = router;