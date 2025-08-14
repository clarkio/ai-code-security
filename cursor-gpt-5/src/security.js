const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { rateLimitWindowMs, rateLimitMax, authRateLimitMax } = require('./config');

function securityHeaders() {
    return helmet({
        contentSecurityPolicy: {
            useDefaults: true,
            directives: {
                "default-src": ["'self'"],
                "script-src": ["'self'"],
                "style-src": ["'self'"],
                "img-src": ["'self'", 'data:'],
                "connect-src": ["'self'"],
                "object-src": ["'none'"],
                "base-uri": ["'self'"],
                "frame-ancestors": ["'none'"],
                "form-action": ["'self'"],
                "upgrade-insecure-requests": [],
            },
        },
        referrerPolicy: { policy: 'no-referrer' },
        crossOriginEmbedderPolicy: true,
        crossOriginOpenerPolicy: { policy: 'same-origin' },
        crossOriginResourcePolicy: { policy: 'same-origin' },
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    });
}

function globalRateLimiter() {
    return rateLimit({
        windowMs: rateLimitWindowMs,
        max: rateLimitMax,
        standardHeaders: true,
        legacyHeaders: false,
    });
}

function authRateLimiter() {
    return rateLimit({
        windowMs: rateLimitWindowMs,
        max: authRateLimitMax,
        standardHeaders: true,
        legacyHeaders: false,
    });
}

function generateCsrfTokenSecret() {
    return crypto.randomBytes(32).toString('hex');
}

module.exports = { securityHeaders, globalRateLimiter, authRateLimiter, generateCsrfTokenSecret };


