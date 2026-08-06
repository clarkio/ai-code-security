const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { User } = require('../models');
const { verifyToken } = require('../middleware/auth');
const { authLimiter, securityLogger } = require('../middleware/security');
const { userValidation } = require('../middleware/validation');

const router = express.Router();

// Generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user.id,
      username: user.username,
      email: user.email
    },
    process.env.JWT_SECRET,
    { 
      expiresIn: '24h',
      issuer: 'notes-app',
      audience: 'notes-app-users'
    }
  );
};

// Register new user
router.post('/register', 
  authLimiter,
  userValidation.register,
  securityLogger('REGISTER_ATTEMPT'),
  async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({
        where: {
          [require('sequelize').Op.or]: [
            { username },
            { email }
          ]
        }
      });

      if (existingUser) {
        return res.status(409).json({
          error: 'User already exists',
          code: 'USER_EXISTS'
        });
      }

      // Create new user
      const user = await User.create({
        username,
        email,
        password
      });

      // Generate token
      const token = generateToken(user);

      // Set session
      req.session.token = token;
      req.session.userId = user.id;

      res.status(201).json({
        message: 'User registered successfully',
        user: user.toJSON(),
        token,
        csrfToken: req.session.csrfToken
      });

    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({
        error: 'Failed to register user',
        code: 'REGISTRATION_ERROR'
      });
    }
  }
);

// Login
router.post('/login',
  authLimiter,
  userValidation.login,
  securityLogger('LOGIN_ATTEMPT'),
  async (req, res) => {
    try {
      const { username, password } = req.body;

      // Find user
      const user = await User.findOne({
        where: { username }
      });

      if (!user) {
        return res.status(401).json({
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        });
      }

      // Check if account is locked
      if (user.isLocked()) {
        return res.status(403).json({
          error: 'Account is locked due to multiple failed login attempts. Please try again later.',
          code: 'ACCOUNT_LOCKED',
          lockedUntil: user.locked_until
        });
      }

      // Validate password
      const isValidPassword = await user.validatePassword(password);

      if (!isValidPassword) {
        await user.incrementFailedAttempts();
        
        return res.status(401).json({
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS',
          remainingAttempts: Math.max(0, 5 - user.failed_login_attempts)
        });
      }

      // Reset failed attempts on successful login
      await user.resetFailedAttempts();

      // Generate token
      const token = generateToken(user);

      // Set session
      req.session.token = token;
      req.session.userId = user.id;

      res.json({
        message: 'Login successful',
        user: user.toJSON(),
        token,
        csrfToken: req.session.csrfToken
      });

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: 'Failed to login',
        code: 'LOGIN_ERROR'
      });
    }
  }
);

// Logout
router.post('/logout',
  verifyToken,
  securityLogger('LOGOUT'),
  (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error('Logout error:', err);
        return res.status(500).json({
          error: 'Failed to logout',
          code: 'LOGOUT_ERROR'
        });
      }

      res.json({
        message: 'Logout successful'
      });
    });
  }
);

// Get current user profile
router.get('/profile',
  verifyToken,
  async (req, res) => {
    try {
      const user = await User.findByPk(req.userId, {
        attributes: { exclude: ['password', 'two_factor_secret'] }
      });

      if (!user) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      res.json({
        user: user.toJSON()
      });

    } catch (error) {
      console.error('Profile fetch error:', error);
      res.status(500).json({
        error: 'Failed to fetch profile',
        code: 'PROFILE_FETCH_ERROR'
      });
    }
  }
);

// Update user profile
router.put('/profile',
  verifyToken,
  userValidation.updateProfile,
  securityLogger('PROFILE_UPDATE'),
  async (req, res) => {
    try {
      const { email, currentPassword, newPassword } = req.body;
      const user = await User.findByPk(req.userId);

      if (!user) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Update email if provided
      if (email && email !== user.email) {
        // Check if email is already taken
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
          return res.status(409).json({
            error: 'Email already in use',
            code: 'EMAIL_EXISTS'
          });
        }
        user.email = email;
      }

      // Update password if provided
      if (newPassword) {
        // Verify current password
        const isValidPassword = await user.validatePassword(currentPassword);
        if (!isValidPassword) {
          return res.status(401).json({
            error: 'Current password is incorrect',
            code: 'INVALID_PASSWORD'
          });
        }
        user.password = newPassword;
      }

      await user.save();

      res.json({
        message: 'Profile updated successfully',
        user: user.toJSON()
      });

    } catch (error) {
      console.error('Profile update error:', error);
      res.status(500).json({
        error: 'Failed to update profile',
        code: 'PROFILE_UPDATE_ERROR'
      });
    }
  }
);

// Refresh token
router.post('/refresh',
  verifyToken,
  async (req, res) => {
    try {
      const user = await User.findByPk(req.userId);
      
      if (!user || !user.is_active) {
        return res.status(401).json({
          error: 'Invalid user',
          code: 'INVALID_USER'
        });
      }

      const token = generateToken(user);
      req.session.token = token;

      res.json({
        token,
        csrfToken: req.session.csrfToken
      });

    } catch (error) {
      console.error('Token refresh error:', error);
      res.status(500).json({
        error: 'Failed to refresh token',
        code: 'REFRESH_ERROR'
      });
    }
  }
);

// Get CSRF token
router.get('/csrf',
  (req, res) => {
    res.json({
      csrfToken: req.session.csrfToken
    });
  }
);

module.exports = router;