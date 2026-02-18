/**
 * Authentication middleware - session check, CSRF
 */
export function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/login');
  }
  next();
}

export function redirectIfAuthenticated(req, res, next) {
  if (req.session?.userId) {
    return res.redirect('/');
  }
  next();
}
