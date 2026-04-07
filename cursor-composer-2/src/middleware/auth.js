/** @param {import('express').Request} req */
export function requireAuth(req, res, next) {
  const uid = req.session?.userId;
  if (typeof uid !== 'number' || !Number.isFinite(uid) || uid < 1) {
    return res.redirect('/login');
  }
  next();
}
