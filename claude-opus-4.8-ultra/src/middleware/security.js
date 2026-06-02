'use strict';

const crypto = require('crypto');

/**
 * Require an authenticated session. Redirects browsers to /login.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.redirect('/login');
}

/**
 * Make auth state available to all templates (e.g. to show username / logout).
 */
function exposeUser(req, res, next) {
  res.locals.currentUser = req.session && req.session.userId
    ? { id: req.session.userId, username: req.session.username }
    : null;
  next();
}

/**
 * CSRF protection using the synchronizer-token pattern.
 *
 * A per-session random token is generated and embedded as a hidden field in
 * every form. On any state-changing request we require the submitted token to
 * match the session token, compared in constant time. Combined with
 * SameSite=Lax cookies this is defence-in-depth against CSRF.
 */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function csrf(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  // Expose to templates so forms can include it.
  res.locals.csrfToken = req.session.csrfToken;

  if (SAFE_METHODS.has(req.method)) return next();

  const submitted =
    (req.body && req.body._csrf) || req.get('x-csrf-token') || '';
  const expected = req.session.csrfToken;

  const submittedBuf = Buffer.from(String(submitted));
  const expectedBuf = Buffer.from(String(expected));

  if (
    submittedBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(submittedBuf, expectedBuf)
  ) {
    return res.status(403).render('error', {
      title: 'Forbidden',
      message: 'Invalid or missing security token. Please reload and try again.',
    });
  }
  return next();
}

module.exports = { requireAuth, exposeUser, csrf };
