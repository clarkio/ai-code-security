'use strict';

const crypto = require('node:crypto');

// Synchronizer-token CSRF protection. The token lives in the session (which is
// keyed by an httpOnly, SameSite=Strict cookie), and every state-changing
// request must echo it back in the form body. Comparison is constant-time.
//
// We only enforce on unsafe methods. SameSite=Strict on the session cookie is
// already a strong CSRF defense; this token is defense-in-depth.

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function ensureToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateToken();
  }
  return req.session.csrfToken;
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function csrfMiddleware(req, res, next) {
  // Always ensure a token exists for the current session so views can render it.
  const token = ensureToken(req);
  res.locals.csrfToken = token;

  if (SAFE_METHODS.has(req.method)) return next();

  const submitted =
    (req.body && typeof req.body._csrf === 'string' && req.body._csrf) ||
    (typeof req.get === 'function' && req.get('x-csrf-token')) ||
    '';

  if (!timingSafeEqualStr(submitted, token)) {
    res.status(403);
    return next(new Error('Invalid CSRF token'));
  }

  return next();
}

// Rotate the CSRF token after privilege boundary transitions (login/logout)
// to prevent token fixation.
function rotateToken(req) {
  req.session.csrfToken = generateToken();
}

module.exports = { csrfMiddleware, rotateToken };
