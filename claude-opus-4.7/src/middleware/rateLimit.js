'use strict';

const rateLimit = require('express-rate-limit');

// Conservative limits. Tune for traffic; defaults assume a small
// single-instance deployment. For multi-instance deployments use a shared
// store (Redis) instead of the in-memory default.

// All requests — protects against generic flooding.
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});

// Login endpoint — strict; per-IP brute-force protection.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  // Do not count successful logins against the bucket.
  skipSuccessfulRequests: true,
  message: 'Too many login attempts. Please try again later.',
});

// Signup endpoint — limit account creation per IP.
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: 'Too many accounts created from this address. Please try again later.',
});

module.exports = { globalLimiter, loginLimiter, signupLimiter };
