'use strict';

const config = require('../config');

function notFoundHandler(req, res) {
  res.status(404).render('error', {
    title: 'Not found',
    status: 404,
    message: 'The page you requested could not be found.',
  });
}

// Express recognizes 4-arg functions as error handlers; do not remove `next`.
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const status = res.statusCode && res.statusCode >= 400 ? res.statusCode : 500;

  // Server-side logging — keep stack traces, redact request body to avoid
  // leaking credentials into logs.
  // eslint-disable-next-line no-console
  console.error(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} -> ${status}`, {
    message: err.message,
    stack: config.isProd ? undefined : err.stack,
  });

  // User-facing message: never leak stack traces or internals.
  const safeMessage =
    status === 403
      ? 'Request rejected.'
      : status === 429
        ? 'Too many requests. Please slow down.'
        : status < 500
          ? err.message || 'Bad request.'
          : 'Something went wrong on our end.';

  if (res.headersSent) {
    return res.end();
  }

  res.status(status).render('error', {
    title: 'Error',
    status,
    message: safeMessage,
  });
}

module.exports = { notFoundHandler, errorHandler };
