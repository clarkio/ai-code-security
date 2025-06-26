const { body, validationResult } = require('express-validator');
const xss = require('xss');

// XSS sanitization options
const xssOptions = {
    whiteList: {
        p: [],
        br: [],
        strong: [],
        em: [],
        u: [],
        ol: [],
        ul: [],
        li: []
    },
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style']
};

// Custom sanitizer for XSS prevention
const sanitizeInput = (value) => {
    if (typeof value !== 'string') return value;
    return xss(value, xssOptions);
};

// Validation rules for user registration
const validateRegistration = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 50 })
        .withMessage('Username must be between 3 and 50 characters')
        .matches(/^[a-zA-Z0-9_-]+$/)
        .withMessage('Username can only contain letters, numbers, hyphens, and underscores')
        .customSanitizer(sanitizeInput),
    
    body('email')
        .trim()
        .isEmail()
        .withMessage('Invalid email format')
        .normalizeEmail()
        .isLength({ max: 100 })
        .withMessage('Email must be less than 100 characters')
        .customSanitizer(sanitizeInput),
    
    body('password')
        .isLength({ min: 8, max: 128 })
        .withMessage('Password must be between 8 and 128 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
        .withMessage('Password must contain uppercase, lowercase, numbers, and special characters')
];

// Validation rules for user login
const validateLogin = [
    body('usernameOrEmail')
        .trim()
        .notEmpty()
        .withMessage('Username or email is required')
        .isLength({ max: 100 })
        .withMessage('Username or email too long')
        .customSanitizer(sanitizeInput),
    
    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ max: 128 })
        .withMessage('Password too long')
];

// Validation rules for note creation/update
const validateNote = [
    body('title')
        .trim()
        .notEmpty()
        .withMessage('Title is required')
        .isLength({ min: 1, max: 200 })
        .withMessage('Title must be between 1 and 200 characters')
        .customSanitizer(sanitizeInput),
    
    body('content')
        .trim()
        .notEmpty()
        .withMessage('Content is required')
        .isLength({ min: 1, max: 10000 })
        .withMessage('Content must be between 1 and 10,000 characters')
        .customSanitizer(sanitizeInput)
];

// Validation rules for note ID parameter
const validateNoteId = [
    body('id')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Invalid note ID')
];

// Middleware to handle validation errors
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        const errorMessages = errors.array().map(error => ({
            field: error.param,
            message: error.msg,
            value: error.value
        }));
        
        return res.status(400).json({
            error: 'Validation failed',
            details: errorMessages
        });
    }
    
    next();
};

// Additional sanitization middleware for all input
const sanitizeAllInput = (req, res, next) => {
    // Recursively sanitize all string values in request body
    const sanitizeObject = (obj) => {
        if (typeof obj === 'string') {
            return sanitizeInput(obj);
        }
        
        if (Array.isArray(obj)) {
            return obj.map(sanitizeObject);
        }
        
        if (obj && typeof obj === 'object') {
            const sanitized = {};
            for (const [key, value] of Object.entries(obj)) {
                sanitized[key] = sanitizeObject(value);
            }
            return sanitized;
        }
        
        return obj;
    };
    
    if (req.body) {
        req.body = sanitizeObject(req.body);
    }
    
    // Sanitize query parameters
    if (req.query) {
        req.query = sanitizeObject(req.query);
    }
    
    next();
};

// Rate limiting validation for sensitive operations
const validateRateLimit = (maxAttempts = 5, windowMs = 15 * 60 * 1000) => {
    const attempts = new Map();
    
    return (req, res, next) => {
        const clientId = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        
        // Clean up old entries
        for (const [id, data] of attempts.entries()) {
            if (now - data.firstAttempt > windowMs) {
                attempts.delete(id);
            }
        }
        
        const clientAttempts = attempts.get(clientId);
        
        if (!clientAttempts) {
            attempts.set(clientId, { count: 1, firstAttempt: now });
            return next();
        }
        
        if (now - clientAttempts.firstAttempt > windowMs) {
            // Reset window
            attempts.set(clientId, { count: 1, firstAttempt: now });
            return next();
        }
        
        if (clientAttempts.count >= maxAttempts) {
            return res.status(429).json({
                error: 'Too many attempts. Please try again later.',
                retryAfter: Math.ceil((windowMs - (now - clientAttempts.firstAttempt)) / 1000)
            });
        }
        
        clientAttempts.count++;
        next();
    };
};

module.exports = {
    validateRegistration,
    validateLogin,
    validateNote,
    validateNoteId,
    handleValidationErrors,
    sanitizeAllInput,
    validateRateLimit,
    sanitizeInput
};
