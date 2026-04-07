import { validateCsrf } from '../lib/csrf.js';

/** @type {import('express').RequestHandler} */
export function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  if (!validateCsrf(req)) {
    return res.status(403).type('html').send('<!DOCTYPE html><title>Forbidden</title><p>Invalid or missing security token. Go back and try again.</p>');
  }
  next();
}
