// middleware/csrfMiddleware.js
const crypto = require('crypto');

function generateCsrfToken(req, res, next) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.csrfToken; // Make it available in templates
    next();
}

function validateCsrfToken(req, res, next) {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next(); // Skip for safe methods
    }

    const tokenFromRequest = req.body._csrf || req.query._csrf || req.headers['x-csrf-token'];

    if (!tokenFromRequest || tokenFromRequest !== req.session.csrfToken) {
        console.warn('CSRF Token Mismatch:', {
            sessionToken: req.session.csrfToken,
            requestToken: tokenFromRequest,
            url: req.originalUrl,
            method: req.method
        });
        req.flash('error', 'Invalid CSRF token. Please try again.');
        return res.status(403).redirect('back'); // Or render an error page
    }
    next();
}

module.exports = { generateCsrfToken, validateCsrfToken };