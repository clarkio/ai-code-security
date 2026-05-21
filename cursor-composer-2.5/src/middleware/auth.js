export function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    req.session.flash = { type: 'error', message: 'Please sign in to continue.' };
    return res.redirect('/login');
  }
  next();
}

export function redirectIfAuthenticated(req, res, next) {
  if (req.session?.userId) {
    return res.redirect('/notes');
  }
  next();
}

export function attachUser(req, res, next) {
  res.locals.currentUser = req.session?.username ?? null;
  res.locals.isAuthenticated = Boolean(req.session?.userId);
  next();
}
