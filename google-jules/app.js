const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const logger = require('./config/logger'); // Winston logger
require('dotenv').config(); // Ensure this is at the top

const authRoutes = require('./routes/authRoutes');
const noteRoutes = require('./routes/noteRoutes'); // Import note routes
const authMiddleware = require('./middleware/authMiddleware'); // Import the middleware

const app = express();

// Security Middlewares
app.use(helmet()); // Set various security HTTP headers

const corsOptions = {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
    optionsSuccessStatus: 200 
};
app.use(cors(corsOptions)); // Enable and configure CORS

app.use(cookieParser()); // Parse cookies, required for csurf

// Body Parsers
app.use(express.json()); // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

// HTTP Request Logging
// Using morgan to stream HTTP logs to Winston
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));


// Rate Limiting - Conditionally apply if not in test environment
if (process.env.NODE_ENV !== 'test') {
    const apiLimiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs for /api/ routes
        standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
        legacyHeaders: false, // Disable the `X-RateLimit-*` headers
        message: 'Too many requests from this IP, please try again after 15 minutes'
    });
    app.use('/api/', apiLimiter);
    logger.info('Rate limiting enabled for API routes.');
} else {
    logger.info('Rate limiting is disabled for test environment.');
}


// CSRF Protection Setup
let csrfSecret = process.env.CSRF_SECRET;
if (process.env.NODE_ENV === 'test' && !csrfSecret) {
    logger.warn('CSRF_SECRET not set for test environment, using default test secret.');
    csrfSecret = 'test_csrf_secret_for_automated_tests_67890!';
} else if (!csrfSecret && process.env.NODE_ENV !== 'test') {
    // In non-test environments, CSRF_SECRET should be set.
    logger.error('FATAL ERROR: CSRF_SECRET is not set. Application is insecure against CSRF attacks.');
    // process.exit(1); // Or handle more gracefully
}

// Csurf middleware - initialized even in test for routes that use it, but cookie options could differ.
// The secret for csurf's cookie is typically managed by cookie-parser's secret,
// or csurf can take a 'cookie: { secret: ... }' option if cookie-parser has no secret.
// For simplicity, we assume cookie-parser handles signed cookies if a secret is provided to it.
// If CSRF_SECRET is used to sign the _csrf cookie, it must be consistent.
// csurf itself uses this secret primarily to verify the token against the cookie.
const csrfProtection = csurf({ 
    cookie: (process.env.NODE_ENV === 'test') 
        ? { key: '_csrf', sameSite: 'lax', httpOnly: true, secure: false } // More lenient for http in tests
        : { key: '_csrf', sameSite: 'lax', httpOnly: true, secure: process.env.NODE_ENV === 'production' } 
    // Note: CSRF secret is not directly configured in csurf like this. It uses req.secret from cookie-parser.
    // If cookie-parser is initialized with a secret, csurf will use that.
    // We are relying on the default behavior. If CSRF_SECRET is meant for cookie signing,
    // it should be passed to cookieParser: app.use(cookieParser(csrfSecret));
});
// For now, let's assume the default csurf({ cookie: true }) is fine and secrets are handled via .env
// The above `csrfSecret` variable isn't directly used by csurf unless we pass it to cookie-parser.
// We will ensure that the cookie-parser middleware is initialized *before* csurf.
// And that CSRF_SECRET in .env is used by cookie-parser if necessary.
// The current csurf setup `csurf({ cookie: true })` relies on `req.secret` if available from `cookieParser(secret)`.
// Or it signs its own cookie if `req.secret` is not available.
// Let's ensure cookieParser has a secret if CSRF_SECRET is defined.

// The original code: app.use(cookieParser());
// If CSRF_SECRET is defined, we should use it for cookie-parser
if (csrfSecret) {
    app.use(cookieParser(csrfSecret));
    logger.info('Cookie parser initialized with CSRF_SECRET.');
} else {
    app.use(cookieParser()); // Default cookie parser without a secret
    logger.warn('Cookie parser initialized WITHOUT a secret. CSRF cookie may not be signed if that was intended.');
}
// We will apply csrfProtection selectively on routes in noteRoutes.js and add a getter route in authRoutes.js.
// Important: The above csrfProtection must be defined *after* app.use(cookieParser(...))


// Mount authentication routes
app.use('/api/auth', authRoutes);

// Serve static files from the 'public' directory
app.use(express.static('public')); 

// Mount note routes
// Note: CSRF protection (defined above) will be applied within noteRoutes.js for state-changing operations
app.use('/api/notes', noteRoutes); 

// Basic root route - Now potentially served by express.static if index.html exists in public
// app.get('/', (req, res) => {
//   res.send('Hello World! Welcome to the Secure Notes API.');
// });

// Example protected route (already exists, good for testing authMiddleware)
app.get('/api/protected-route', authMiddleware, (req, res) => {
    res.json({ message: 'You are authorized!', userId: req.user.id });
});

// Global error handler
// This needs to be after all other app.use() and routes calls
app.use((err, req, res, next) => {
    // Log the error using Winston
    logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip} - Stack: ${err.stack}`);

    // Handle CSRF token errors
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ message: 'Invalid CSRF token. Please refresh and try again.' });
    }

    // Handle express-validator errors (if not handled locally by routes)
    // This check might need adjustment based on how validation errors are structured if they reach here.
    if (err.errors && Array.isArray(err.errors)) { 
        return res.status(400).json({ errors: err.errors });
    }
    
    // Handle other known error types if necessary
    // if (err instanceof SomeKnownError) { ... }

    // Send generic error message to the client
    res.status(err.status || 500).json({
        message: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred on the server.' : err.message
    });
});


// Start server only if this file is run directly
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      logger.info(`Server is running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
    });
}

module.exports = app; // Export for potential testing
