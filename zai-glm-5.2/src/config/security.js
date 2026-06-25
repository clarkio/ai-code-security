"use strict";

/**
 * Centralized security configuration.
 * All security-sensitive settings live here so they can be audited in one place.
 */

const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const hpp = require("hpp");

const config = require("./env");

// --- Content Security Policy ---
// Strict CSP: only allow self for scripts/styles, no inline, no external origins.
// Nonces are NOT used here because we avoid inline scripts entirely.
const cspOptions = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:"],
    fontSrc: ["'self'"],
    connectSrc: ["'self'"],
    frameAncestors: ["'none'"],
    formAction: ["'self'"],
    baseUri: ["'self'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
  },
  // Don't leak the report URI or expose internals
  reportOnly: false,
};

// --- Helmet config (secure headers) ---
const helmetConfig = {
  contentSecurityPolicy: cspOptions,
  crossOriginEmbedderPolicy: false, // COEP can break external resources; we lock down via CSP instead
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "same-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: "deny" },
  hsts: {
    maxAge: 63072000, // 2 years
    includeSubDomains: true,
    preload: true,
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: "none" },
  referrerPolicy: { policy: "no-referrer" },
  xssFilter: true, // Legacy; modern browsers use CSP. Harmless.
};

// --- Rate limiting ---
// General API limiter
const apiLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
  // Skip when explicitly disabled (testing only)
  skip: () => config.disableRateLimit,
});

// Stricter limiter for auth endpoints (brute-force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many login attempts. Please try again in 15 minutes.",
  },
  skipSuccessfulRequests: true, // Don't count successful logins
  skip: () => config.disableRateLimit,
});

// Stricter limiter for note creation (abuse prevention)
const writeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 writes per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please slow down." },
  skip: () => config.disableRateLimit,
});

module.exports = {
  helmet: helmet(helmetConfig),
  apiLimiter,
  authLimiter,
  writeLimiter,
  // Mongo-style query injection sanitizer (defense in depth even though we use SQL)
  mongoSanitize: mongoSanitize(),
  // HTTP Parameter Pollution protection
  hpp: hpp(),
};
