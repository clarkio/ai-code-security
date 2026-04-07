import crypto from 'node:crypto';

const CSRF_BYTES = 32;

export function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(CSRF_BYTES).toString('base64url');
  }
  return req.session.csrfToken;
}

/**
 * @param {string} a
 * @param {string} b
 */
export function timingSafeEqualString(a, b) {
  const bufA = Buffer.from(String(a), 'utf8');
  const bufB = Buffer.from(String(b), 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/** @param {import('express').Request} req */
export function validateCsrf(req) {
  const fromBody = req.body && typeof req.body._csrf === 'string' ? req.body._csrf : '';
  const sessionToken = req.session && req.session.csrfToken ? req.session.csrfToken : '';
  return Boolean(fromBody && sessionToken && timingSafeEqualString(fromBody, sessionToken));
}
