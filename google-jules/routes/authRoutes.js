const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const rateLimit = require('express-rate-limit');
const csurf = require('csurf'); // Import csurf
const router = express.Router();

// CSRF protection middleware setup
// Note: csurf is usually initialized in app.js and passed or applied here.
// For this task, we are following the instruction to initialize it in app.js
// and apply it here.
const csrfProtection = csurf({ cookie: true }); // As per app.js setup

// Stricter rate limiter for authentication routes - conditionally apply
let authLimiter = (req, res, next) => next(); // Default to no-op
if (process.env.NODE_ENV !== 'test') {
    authLimiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 10, // Limit each IP to 10 login/register attempts per windowMs
        message: 'Too many authentication attempts from this IP, please try again after 15 minutes',
        standardHeaders: true,
        legacyHeaders: false,
    });
    console.log('Auth rate limiting enabled.');
} else {
    console.log('Auth rate limiting is disabled for test environment.');
}

// Validation middleware for registration
const registerValidation = [
    body('username', 'Username is required').not().isEmpty().trim().escape(),
    body('email', 'Please include a valid email').isEmail().normalizeEmail(),
    body('password', 'Password must be 6 or more characters').isLength({ min: 6 })
];

// Validation middleware for login
const loginValidation = [
    body('email', 'Please include a valid email').isEmail().normalizeEmail(),
    body('password', 'Password is required').exists()
];

// POST /api/auth/register
router.post('/register', authLimiter, registerValidation, authController.register);

// POST /api/auth/login
router.post('/login', authLimiter, loginValidation, authController.login);

// GET /api/auth/csrf-token - Route to provide CSRF token to clients
router.get('/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

module.exports = router;
