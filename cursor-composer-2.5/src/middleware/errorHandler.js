export function notFoundHandler(req, res) {
  res.status(404).render('error', {
    title: 'Not found',
    message: 'The page you requested does not exist.',
    statusCode: 404,
  });
}

export function errorHandler(err, req, res, _next) {
  if (err.code === 'EBADCSRFTOKEN') {
    req.session.flash = {
      type: 'error',
      message: 'Invalid or expired form submission. Please try again.',
    };
    const referer = req.get('Referer');
    const target =
      referer && new URL(referer, `${req.protocol}://${req.get('host')}`).origin ===
        `${req.protocol}://${req.get('host')}`
        ? referer
        : '/login';
    return res.redirect(target);
  }

  console.error('Unhandled error:', err.message);
  res.status(500).render('error', {
    title: 'Error',
    message: 'Something went wrong. Please try again later.',
    statusCode: 500,
  });
}
