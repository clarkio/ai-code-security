import { config } from '../config.js';

/** @type {import('express').ErrorRequestHandler} */
export function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    return next(err);
  }
  // eslint-disable-next-line no-console
  console.error(err);
  const status = err.status && Number.isInteger(err.status) ? err.status : 500;
  const message = config.isProd && status >= 500 ? 'Something went wrong.' : err.message || 'Error';
  res.status(status).type('html').send(`<!DOCTYPE html><title>Error</title><p>${escapeHtml(message)}</p>`);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
