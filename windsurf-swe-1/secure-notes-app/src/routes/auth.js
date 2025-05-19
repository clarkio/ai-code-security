const express = require('express');
const authController = require('../controllers/authController');
const { body, query, param } = require('express-validator');
const auth = require('../middlewares/auth');

const router = express.Router();

// Apply rate limiting to auth routes
router.use(authController.authLimiter);

// Input validation middleware
const validateSignup = [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters long')
    .matches(/\d/)
    .withMessage('Password must contain at least one number')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[^a-zA-Z0-9]/)
    .withMessage('Password must contain at least one special character'),
  body('passwordConfirm')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    })
    .withMessage('Passwords do not match'),
];

const validateLogin = [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').exists().withMessage('Please provide a password'),
];

const validateForgotPassword = [
  body('email').isEmail().withMessage('Please provide a valid email'),
];

const validateResetPassword = [
  body('password')
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters long')
    .matches(/\d/)
    .withMessage('Password must contain at least one number')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[^a-zA-Z0-9]/)
    .withMessage('Password must contain at least one special character'),
  body('passwordConfirm')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    })
    .withMessage('Passwords do not match'),
];

// Public routes
router.post('/signup', validateSignup, authController.signup);
router.post('/login', validateLogin, authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/logout', authController.logout);

// Password reset routes
router.post('/forgot-password', validateForgotPassword, authController.forgotPassword);
router.post('/reset-password/:token', validateResetPassword, authController.resetPassword);

// 2FA routes
router.post('/2fa/setup', authController.protect, authController.setupTwoFactor);
router.post('/2fa/verify', authController.protect, authController.verifyTwoFactor);
router.post('/2fa/disable', authController.protect, authController.disableTwoFactor);
router.post('/2fa/verify-recovery', authController.verifyTwoFactorRecovery);

// Protect all routes after this middleware
router.use(authController.protect);

// User profile routes
router.get('/me', authController.getMe, authController.getUser);

// Update current user's profile
router.patch(
  '/update-me',
  [
    body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
    body('email')
      .optional()
      .isEmail()
      .withMessage('Please provide a valid email')
      .normalizeEmail(),
    body('currentPassword')
      .if(body('email').exists() || body('password').exists())
      .notEmpty()
      .withMessage('Current password is required to update email or password'),
  ],
  authController.updateMe
);

// Update password for logged-in users
router.patch(
  '/update-password',
  [
    body('currentPassword').notEmpty().withMessage('Please provide your current password'),
    body('newPassword')
      .isLength({ min: 12 })
      .withMessage('Password must be at least 12 characters long')
      .matches(/\d/)
      .withMessage('Password must contain at least one number')
      .matches(/[a-z]/)
      .withMessage('Password must contain at least one lowercase letter')
      .matches(/[A-Z]/)
      .withMessage('Password must contain at least one uppercase letter')
      .matches(/[^a-zA-Z0-9]/)
      .withMessage('Password must contain at least one special character'),
    body('newPasswordConfirm')
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error('Password confirmation does not match new password');
        }
        return true;
      })
      .withMessage('Passwords do not match'),
  ],
  authController.updatePassword
);

// Delete current user's account
router.delete('/delete-me', authController.deleteMe);

// Session management
router.get('/sessions', authController.getActiveSessions);
router.delete('/sessions/:sessionId', authController.revokeSession);
router.delete('/sessions', authController.revokeAllSessions);

// Admin only routes
router.use(authController.restrictTo('admin'));

// User management (admin only)
router.get('/', authController.getAllUsers);
router.post('/:id/lock', authController.lockUserAccount);
router.post('/:id/unlock', authController.unlockUserAccount);

// Get, update, delete user by ID (admin only)
router
  .route('/:id')
  .get(authController.getUser)
  .patch(authController.updateUser)
  .delete(authController.deleteUser);

module.exports = router;
