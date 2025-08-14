import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

export function getCspDirectives() {
    return {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        blockAllMixedContent: [],
        fontSrc: ["'self'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'"],
        upgradeInsecureRequests: []
    };
}

export function getHelmetConfig() {
    return {
        contentSecurityPolicy: {
            useDefaults: true,
            directives: getCspDirectives()
        },
        crossOriginResourcePolicy: { policy: 'same-origin' },
        frameguard: { action: 'deny' },
        referrerPolicy: { policy: 'no-referrer' },
        hsts: process.env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false
    };
}

export function buildRateLimiter({ windowMs = 60_000, max = 100, standardHeaders = true, legacyHeaders = false, message = 'Too many requests, please try again later.' } = {}) {
    return rateLimit({ windowMs, max, standardHeaders, legacyHeaders, message });
}


