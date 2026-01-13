const express = require('express');
const { body } = require('express-validator');
const { registerUser, authenticateUser, generateTokens, storeRefreshToken, revokeRefreshToken, getUserById } = require('../lib/auth');
const { validate, usernameValidator, emailValidator, passwordValidator } = require('../middleware/validation');
const { sanitizePlainText, sanitizeHTML } = require('../lib/sanitizer');
const { authLimiter } = require('../middleware/security');

const router = express.Router();

router.post('/register',
  authLimiter,
  [
    usernameValidator,
    emailValidator,
    passwordValidator,
    body('confirmPassword')
      .custom((value, { req }) => value === req.body.password)
      .withMessage('Passwords do not match')
  ],
  validate,
  async (req, res) => {
    try {
      const sanitizedUsername = sanitizePlainText(req.body.username);
      const sanitizedEmail = sanitizeHTML(req.body.email, [], []);

      const user = await registerUser(sanitizedUsername, sanitizedEmail, req.body.password);

      res.status(201).json({
        message: 'User registered successfully',
        user: { id: user.id, username: user.username, email: user.email }
      });
    } catch (error) {
      if (error.message.includes('already exists')) {
        return res.status(409).json({ error: error.message });
      }
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

router.post('/login',
  authLimiter,
  [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  validate,
  async (req, res) => {
    try {
      const sanitizedUsername = sanitizePlainText(req.body.username);
      const user = await authenticateUser(sanitizedUsername, req.body.password);

      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const { accessToken, refreshToken } = generateTokens(user.id);

      await storeRefreshToken(
        user.id,
        refreshToken,
        req.headers['user-agent'] || 'unknown',
        req.ip || req.connection.remoteAddress
      );

      res.json({
        message: 'Login successful',
        user: { id: user.id, username: user.username, email: user.email },
        accessToken,
        refreshToken
      });
    } catch (error) {
      if (error.message.includes('locked')) {
        return res.status(423).json({ error: error.message });
      }
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  try {
    const isValid = await isTokenValid(refreshToken);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const decoded = require('jsonwebtoken').decode(refreshToken);
    const user = getUserById(decoded.userId);

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    const tokens = generateTokens(user.id);

    await revokeRefreshToken(refreshToken);
    await storeRefreshToken(
      user.id,
      tokens.refreshToken,
      req.headers['user-agent'] || 'unknown',
      req.ip || req.connection.remoteAddress
    );

    res.json({ accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });
  } catch {
    res.status(401).json({ error: 'Token refresh failed' });
  }
});

router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    await revokeRefreshToken(refreshToken);
  }

  res.json({ message: 'Logged out successfully' });
});

module.exports = router;
